"""国内版手机号验证码登录。

看板先用现有的 POST /accounts/login/start 拿到 hub state。本模块接着做
codebuddy.cn 上的风控票据、短信发送、验码和 bind。bind 把同一个 state
标记为已登录之后，原有的 GET /accounts/login/poll 会把 token 收进账号池。

设备票据不写进源码。读取顺序：环境变量 WB_CN_DEVICE_TOKEN、
accounts/device-token.txt、flow/repro/device-token.txt。
"""
import base64
import json
import os
import re
import ssl
import threading
import urllib.error
import urllib.parse
import urllib.request

ORIGIN = "https://www.codebuddy.cn"
KC = ORIGIN + "/auth/realms/copilot"
BROWSER_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:152.0) Gecko/20100101 Firefox/152.0"
ONEID = "https://oauth2.account.tencent.com"


class SmsLoginError(Exception):
    pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def http_error_302(self, req, fp, code, msg, headers):
        return fp

    http_error_301 = http_error_303 = http_error_307 = http_error_308 = http_error_302


def _default_transport(url, method, headers, body, timeout=30):
    data = body.encode("utf-8") if isinstance(body, str) else body
    request = urllib.request.Request(url, data=data, method=method or "GET", headers=headers or {})
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        response = opener.open(request, timeout=timeout)
    except urllib.error.HTTPError as exc:
        response = exc
    except Exception as exc:
        raise SmsLoginError("连接上游失败: %s" % exc)
    try:
        raw = response.read()
    finally:
        response.close()
    text = raw.decode("utf-8", "replace")
    header_map = {}
    message = response.headers
    for key in ("location",):
        value = message.get(key)
        if value:
            header_map[key] = value
    cookies = message.get_all("Set-Cookie") if hasattr(message, "get_all") else None
    if cookies:
        header_map["set-cookie"] = list(cookies)
    return response.status, header_map, text


class CookieJar(object):
    """Same-name cookies on different paths stay separate. The longest path wins."""

    def __init__(self):
        self._jars = {}

    def store(self, url, set_cookies):
        if not set_cookies:
            return
        host = urllib.parse.urlparse(url).hostname
        jar = self._jars.setdefault(host, {})
        for raw in set_cookies:
            parts = raw.split(";")
            name_value = parts[0]
            index = name_value.find("=")
            if index < 0:
                continue
            name = name_value[:index].strip()
            value = name_value[index + 1:].strip()
            path = "/"
            for attr in parts[1:]:
                item = attr.strip()
                if item.lower().startswith("path="):
                    path = item[5:].strip() or "/"
            key = name + "|" + path
            if value == "" or re.search(r"Max-Age=0($|;)", raw, re.I):
                jar.pop(key, None)
            else:
                jar[key] = (name, value, path)

    def header(self, url):
        parsed = urllib.parse.urlparse(url)
        jar = self._jars.get(parsed.hostname)
        if not jar:
            return None
        path = parsed.path or "/"
        hits = [item for item in jar.values() if path.startswith(item[2])]
        hits.sort(key=lambda item: len(item[2]), reverse=True)
        seen = set()
        parts = []
        for name, value, _path in hits:
            if name in seen:
                continue
            seen.add(name)
            parts.append(name + "=" + value)
        return "; ".join(parts) if parts else None


def load_device_token(accounts_dir=None):
    env = os.environ.get("WB_CN_DEVICE_TOKEN", "").strip()
    if env:
        return env
    root = os.path.dirname(os.path.abspath(__file__))
    candidates = []
    if accounts_dir:
        candidates.append(os.path.join(accounts_dir, "device-token.txt"))
    candidates.append(os.path.join(root, "flow", "repro", "device-token.txt"))
    for path in candidates:
        if not path or not os.path.isfile(path):
            continue
        with open(path, encoding="utf-8") as handle:
            text = handle.read().strip()
        if text:
            return text
    return ""


def normalize_mobile(raw):
    text = re.sub(r"[\s\-]", "", str(raw or ""))
    if text.startswith("+86"):
        digits = text[3:]
    elif text.startswith("86") and len(text) == 13:
        digits = text[2:]
    else:
        digits = text
    if not re.fullmatch(r"1\d{10}", digits):
        raise SmsLoginError("请输入 11 位国内手机号")
    return "+86 " + digits


def _json_body(text):
    try:
        value = json.loads(text)
    except Exception:
        return None
    return value if isinstance(value, dict) else None


def _upstream_message(status, text):
    body = _json_body(text) or {}
    message = body.get("msg") or body.get("error") or body.get("message") or ""
    code = body.get("code")
    if message and code not in (None, 0, "0"):
        return "%s (code %s)" % (message, code)
    if message:
        return str(message)
    snippet = (text or "").strip().replace("\n", " ")
    if len(snippet) > 180:
        snippet = snippet[:180] + "..."
    return "上游返回 %s %s" % (status, snippet or "空响应")


class SmsLogin(object):
    def __init__(self, hub_state, device_token, transport=None):
        self.hub_state = str(hub_state or "")
        self.device_token = device_token or ""
        self.transport = transport or _default_transport
        self.jar = CookieJar()
        self.login_risk_state = ""
        self.session_code = ""
        self.tab_id = ""
        self.client_data = ""
        self.state_token = ""
        self.mobile = ""

    def _request(self, url, method="GET", headers=None, body=None):
        outgoing = {"User-Agent": BROWSER_UA, "Accept-Language": "zh-CN,zh;q=0.9"}
        if headers:
            outgoing.update(headers)
        cookie = self.jar.header(url)
        if cookie and "Cookie" not in outgoing and "cookie" not in outgoing:
            outgoing["Cookie"] = cookie
        status, response_headers, text = self.transport(url, method, outgoing, body)
        self.jar.store(url, (response_headers or {}).get("set-cookie"))
        return status, response_headers or {}, text

    def prepare(self):
        self.state_token = ""
        if not self.hub_state:
            raise SmsLoginError("缺少登录 state，请重新打开添加账号")
        if not self.device_token:
            raise SmsLoginError(
                "缺少国内版设备票据。把 x-device-token 放到 accounts/device-token.txt，"
                "或设置环境变量 WB_CN_DEVICE_TOKEN")
        referer = ORIGIN + "/login/?platform=CLI&state=" + urllib.parse.quote(self.hub_state)
        status, _headers, text = self._request(
            ORIGIN + "/console/auth/risk-context?platform=CLI",
            method="POST",
            headers={
                "Origin": ORIGIN,
                "Referer": referer,
                "Accept": "*/*",
                "x-device-token": self.device_token,
            },
        )
        body = _json_body(text) or {}
        risk = ((body.get("data") or {}) if isinstance(body.get("data"), dict) else {}).get("state")
        if status != 200 or body.get("code") != 0 or not risk:
            raise SmsLoginError("风控票据失败: " + _upstream_message(status, text))
        self.login_risk_state = str(risk)

        redirect = ORIGIN + "/login/?platform=CLI&state=" + urllib.parse.quote(self.hub_state)
        auth_url = (KC + "/protocol/openid-connect/auth?client_id=console&response_type=code&redirect_uri="
                    + urllib.parse.quote(redirect, safe=""))
        status, _headers, html = self._request(auth_url, headers={"Accept": "text/html,application/xhtml+xml"})
        if status != 200:
            raise SmsLoginError("登录页打开失败: " + _upstream_message(status, html))
        session = re.search(r"session_code=([A-Za-z0-9_\-]+)", html or "")
        tab = re.search(r"tab_id=([A-Za-z0-9_\-]+)", html or "")
        client = re.search(
            r"broker/oneid/login\?client_id=console&(?:amp;)?tab_id=[A-Za-z0-9_\-]+&(?:amp;)?client_data=([A-Za-z0-9_\-%=]+)",
            html or "")
        self.session_code = session.group(1) if session else ""
        self.tab_id = tab.group(1) if tab else ""
        if client:
            self.client_data = urllib.parse.unquote(client.group(1))
        else:
            self.client_data = base64.b64encode(
                json.dumps({"ru": redirect, "rt": "code"}, separators=(",", ":")).encode("utf-8")
            ).decode("ascii")
        if not self.session_code or not self.tab_id:
            raise SmsLoginError("登录页里没有 session_code / tab_id，请重新生成登录")
        return self

    def send(self, mobile):
        self.mobile = normalize_mobile(mobile)
        self.prepare()
        payload = {
            "spi_extra": json.dumps({
                "v": 1,
                "state": self.login_risk_state,
                "src": "oneid_pc",
                "biz": "login",
            }, separators=(",", ":")),
            "client_code": "codebuddy",
            "mobile": self.mobile,
            "scopes": ["openid", "mobile", "profile"],
        }
        status, _headers, text = self._request(
            ONEID + "/v1/auth/sms/code/send",
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "Origin": ORIGIN,
                "Referer": ORIGIN + "/",
                "x-toa-lang": "zh-CN",
            },
            body=json.dumps(payload, separators=(",", ":")),
        )
        body = _json_body(text) or {}
        if body.get("captcha"):
            raise SmsLoginError("这个手机号发送太频繁，上游要求图形验证码。请过一会儿再试，或改用浏览器链接登录。")
        token = body.get("state_token")
        if status != 200 or not token:
            raise SmsLoginError("验证码发送失败: " + _upstream_message(status, text))
        self.state_token = str(token)
        try:
            expires = int(body.get("expires_in") or 60)
        except (TypeError, ValueError):
            expires = 60
        return {"expiresIn": expires, "mobile": self.mobile}

    def verify_and_bind(self, code):
        code = str(code or "").strip()
        if not re.fullmatch(r"\d{4,8}", code):
            raise SmsLoginError("请输入短信里的验证码")
        if not self.state_token:
            raise SmsLoginError("还没有发送验证码")
        self._verify(code)
        oneid_code = self._oneid_accounts()
        broker_state, broker_redirect = self._broker_login()
        self._follow_to_login(broker_redirect, oneid_code, broker_state)
        self._console_session()
        self._enterprise()
        self._bind()

    def _verify(self, code):
        status, _headers, text = self._request(
            ONEID + "/v1/auth/sms/code/verify",
            method="POST",
            headers=self._oneid_headers(),
            body=json.dumps({"state_token": self.state_token, "code": code}, separators=(",", ":")),
        )
        if status != 200:
            raise SmsLoginError("验证码校验失败: " + _upstream_message(status, text))

    def _oneid_accounts(self):
        status, _headers, text = self._request(
            ONEID + "/v1/auth/accounts?state_token=" + urllib.parse.quote(self.state_token),
            headers=self._oneid_headers(),
        )
        body = _json_body(text) or {}
        oneid_code = body.get("code")
        if status != 200 or not isinstance(oneid_code, str) or not oneid_code:
            raise SmsLoginError("账号确认失败: " + _upstream_message(status, text))
        return oneid_code

    def _broker_login(self):
        url = (KC + "/broker/oneid/login?client_id=console&tab_id=" + urllib.parse.quote(self.tab_id)
               + "&client_data=" + urllib.parse.quote(self.client_data, safe="")
               + "&session_code=" + urllib.parse.quote(self.session_code, safe="")
               + "&from_oneid_login=true")
        status, _headers, text = self._request(url, headers={
            "Accept": "application/json, text/plain, */*",
            "Referer": ORIGIN + "/login/?platform=CLI&state=" + self.hub_state,
        })
        body = _json_body(text) or {}
        if status != 200 or body.get("code") != 0 or not body.get("state") or not body.get("redirect_uri"):
            raise SmsLoginError("授权桥接失败: " + _upstream_message(status, text))
        return body["state"], body["redirect_uri"]

    def _follow_to_login(self, redirect_uri, oneid_code, broker_state):
        url = urllib.parse.urljoin(ORIGIN + "/", redirect_uri)
        joiner = "&" if "?" in url else "?"
        url = url + joiner + urllib.parse.urlencode({"code": oneid_code, "state": broker_state})
        referer = ORIGIN + "/login/?platform=CLI&state=" + self.hub_state
        for hop in range(8):
            status, headers, text = self._request(url, headers={
                "Accept": "text/html,application/xhtml+xml",
                "Referer": referer,
            })
            location = headers.get("location")
            if status not in (301, 302, 303, 307, 308) or not location:
                raise SmsLoginError("授权跳转在第 %d 步停下: %s" % (hop, _upstream_message(status, text)))
            url = urllib.parse.urljoin(url, location)
            if url.startswith(ORIGIN + "/login/"):
                query = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
                if (query.get("code") or [""])[0]:
                    return
                raise SmsLoginError("授权跳转没有带回登录码")
        raise SmsLoginError("授权跳转次数过多")

    def _console_session(self):
        url = ORIGIN + "/console/accounts"
        for hop in range(8):
            status, headers, text = self._request(url, headers={"Accept": "application/json, text/plain, */*"})
            body = _json_body(text) or {}
            if status == 200 and body.get("code") == 0:
                return
            location = headers.get("location")
            if not location:
                raise SmsLoginError("控制台会话在第 %d 步停下: %s" % (hop, _upstream_message(status, text)))
            url = urllib.parse.urljoin(url, location)
        raise SmsLoginError("控制台会话没有建立")

    def _enterprise(self):
        status, _headers, text = self._request(
            ORIGIN + "/console/login/enterprise?state=" + urllib.parse.quote(self.hub_state),
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json, text/plain, */*",
                "Origin": ORIGIN,
                "Referer": ORIGIN + "/login/?platform=CLI&state=" + self.hub_state,
            },
            body="{}",
        )
        body = _json_body(text) or {}
        data = body.get("data") if isinstance(body.get("data"), dict) else {}
        if status != 200 or body.get("code") != 0 or not data.get("accessToken"):
            raise SmsLoginError("换取令牌失败: " + _upstream_message(status, text))

    def _bind(self):
        url = (ORIGIN + "/console/auth/login?platform=CLI&state=" + urllib.parse.quote(self.hub_state)
               + "&domain=www.codebuddy.cn")
        status, headers, text = self._request(url, headers={
            "Accept": "application/json, text/plain, */*",
            "Referer": ORIGIN + "/login/?platform=CLI&state=" + self.hub_state,
        })
        location = headers.get("location")
        if status in (301, 302, 303, 307, 308) and location:
            self._request(urllib.parse.urljoin(url, location), headers={"Accept": "text/html,application/xhtml+xml"})
            return
        if status == 200:
            return
        raise SmsLoginError("登录确认失败: " + _upstream_message(status, text))

    def _oneid_headers(self):
        return {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Origin": ORIGIN,
            "Referer": ORIGIN + "/",
            "x-toa-lang": "zh-CN",
        }


_lock = threading.Lock()
_sessions = {}
_TTL_SECONDS = 600


def drop(state):
    with _lock:
        _sessions.pop(str(state or ""), None)


def session_for(state, device_token, transport=None, now=None):
    import time
    clock = time.time if now is None else (lambda: now)
    key = str(state or "")
    with _lock:
        stale = [item for item, (created, _session) in _sessions.items()
                 if clock() - created > _TTL_SECONDS]
        for item in stale:
            _sessions.pop(item, None)
        found = _sessions.get(key)
        if found and transport is None:
            return found[1]
        created = _sessions[key][0] if found else clock()
        login = SmsLogin(key, device_token, transport=transport)
        _sessions[key] = (created, login)
        return login
