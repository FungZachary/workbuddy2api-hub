"""国内版手机号登录：票据、发码、验码接在已有的 hub state 上。"""
import json
import os
import sys
import threading
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import wb_cn_sms
import wb_proxy as proxy


HUB = "hub-state-1"
KC_HTML = (
    '<html><a href="/auth/realms/copilot/broker/oneid/login?client_id=console'
    '&amp;tab_id=tab999&amp;session_code=sess123&amp;client_data=Y2Q%3D">'
    'session_code=sess123 tab_id=tab999</a></html>'
)


class Scripted(object):
    def __init__(self, replies):
        self.replies = list(replies)
        self.calls = []

    def __call__(self, url, method, headers, body, timeout=30):
        self.calls.append({
            "url": url,
            "method": method,
            "headers": dict(headers or {}),
            "body": body,
        })
        if not self.replies:
            raise AssertionError("unexpected call %s %s" % (method, url))
        status, response_headers, text = self.replies.pop(0)
        return status, response_headers, text


def reply(status, payload, headers=None):
    if isinstance(payload, str):
        text = payload
    else:
        text = json.dumps(payload)
    return status, dict(headers or {}), text


class CookieAndMobileTests(unittest.TestCase):
    def test_cookie_keeps_paths_and_prefers_the_longer_one(self):
        jar = wb_cn_sms.CookieJar()
        jar.store("https://www.codebuddy.cn/auth/realms/copilot/login", [
            "session=root; Path=/",
            "session=auth; Path=/auth",
            "login_risk_state=risk; Path=/auth",
            "gone=; Path=/; Max-Age=0",
        ])
        header = jar.header("https://www.codebuddy.cn/auth/realms/copilot/broker")
        self.assertIn("session=auth", header)
        self.assertNotIn("session=root", header)
        self.assertIn("login_risk_state=risk", header)
        self.assertNotIn("gone=", header)

    def test_mobile_accepts_an_11_digit_number(self):
        self.assertEqual(wb_cn_sms.normalize_mobile("13800138000"), "+86 13800138000")
        self.assertEqual(wb_cn_sms.normalize_mobile("+86 138-0013-8000"), "+86 13800138000")
        with self.assertRaises(wb_cn_sms.SmsLoginError):
            wb_cn_sms.normalize_mobile("12345")


class SmsFlowTests(unittest.TestCase):
    def tearDown(self):
        wb_cn_sms.drop(HUB)

    def test_send_then_verify_follows_the_hub_state(self):
        script = Scripted([
            reply(200, {"code": 0, "data": {"state": "risk-1"}},
                  {"set-cookie": ["login_risk_state=risk-1; Path=/auth"]}),
            reply(200, KC_HTML, {"set-cookie": ["AUTH_SESSION_ID=kc; Path=/auth/realms/copilot/"]}),
            reply(200, {"captcha": None, "expires_in": 60, "state_token": "sl_token"}),
            reply(200, {"state_token": "sl_token"}),
            reply(200, {"code": "oneid-code", "accounts": [{"uid": "u"}], "next_step": "login"}),
            reply(200, {"code": 0, "state": "broker-state",
                        "redirect_uri": "https://www.codebuddy.cn/auth/realms/copilot/broker/oneid/endpoint"}),
            reply(302, "", {"location": "https://www.codebuddy.cn/login/?platform=CLI&state=%s&code=kc-code" % HUB}),
            reply(200, {"code": 0, "data": {"accounts": [{"uid": "u", "nickname": "n"}]}}),
            reply(200, {"code": 0, "data": {"accessToken": "access-token", "refreshToken": "refresh-token"}}),
            reply(302, "", {"location": "https://www.codebuddy.cn/login/?platform=CLI&state=%s" % HUB}),
            reply(200, "ok"),
        ])
        login = wb_cn_sms.SmsLogin(HUB, "device-token", transport=script)
        sent = login.send("13800138000")
        self.assertEqual(sent["expiresIn"], 60)
        self.assertEqual(sent["mobile"], "+86 13800138000")
        send_call = script.calls[2]
        self.assertIn("risk-1", send_call["body"])
        self.assertIn("+86 13800138000", send_call["body"])
        login.verify_and_bind("123456")
        broker = next(call for call in script.calls if "/broker/oneid/login" in call["url"])
        self.assertIn("AUTH_SESSION_ID=kc", broker["headers"].get("Cookie", ""))
        self.assertIn("state=" + HUB, script.calls[-2]["url"])
        self.assertEqual(script.replies, [])

    def test_captcha_stops_the_send(self):
        script = Scripted([
            reply(200, {"code": 0, "data": {"state": "risk-1"}}),
            reply(200, KC_HTML),
            reply(200, {"captcha": {"appId": "1"}, "state_token": ""}),
        ])
        login = wb_cn_sms.SmsLogin(HUB, "device-token", transport=script)
        with self.assertRaises(wb_cn_sms.SmsLoginError) as caught:
            login.send("13800138000")
        self.assertIn("图形验证码", str(caught.exception))

    def test_verify_without_a_code_does_not_call_upstream(self):
        script = Scripted([])
        login = wb_cn_sms.SmsLogin(HUB, "device-token", transport=script)
        login.state_token = "sl_token"
        with self.assertRaises(wb_cn_sms.SmsLoginError):
            login.verify_and_bind("")
        self.assertEqual(script.calls, [])


class FakePool(object):
    def __init__(self):
        self.logins = {}
        self._lock = threading.Lock()
        self.polled = []

    def poll_login(self, state):
        self.polled.append(state)
        return {"status": "ok", "account": {"uid": "u", "nickname": "n"}}


class RouteTests(unittest.TestCase):
    def setUp(self):
        self.pool = FakePool()
        self.pool.logins["live"] = {"realm": "cn", "platform": "CLI", "created": 0}

        def _error(status, message, kind="invalid_request_error"):
            return ("error", status, message, kind)

        def _json(status, payload):
            return (status, payload)

        self.handler = type("Handler", (), {
            "_error": staticmethod(_error),
            "_json": staticmethod(_json),
        })()
        self.handler._cn_sms_login = proxy.Handler._cn_sms_login.__get__(self.handler)

    def route(self, method, payload):
        with mock.patch.object(proxy, "POOL", self.pool), \
             mock.patch.object(proxy, "log", lambda *args, **kwargs: None):
            return method(self.handler, payload)

    def test_send_rejects_an_unknown_login(self):
        kind, status, message, code = self.route(
            proxy.Handler._route_accounts_login_sms_send,
            {"state": "missing", "mobile": "13800138000"})
        self.assertEqual(kind, "error")
        self.assertEqual(status, 400)
        self.assertIn("不存在", message)
        self.assertEqual(code, "invalid_request_error")

    def test_send_rejects_the_international_realm(self):
        self.pool.logins["live"]["realm"] = "intl"
        _kind, _status, message, _code = self.route(
            proxy.Handler._route_accounts_login_sms_send,
            {"state": "live", "mobile": "13800138000"})
        self.assertIn("国内版", message)

    def test_verify_polls_the_same_state(self):
        class Login(object):
            hub_state = "live"

            def verify_and_bind(self, code):
                self.code = code

        login = Login()
        with mock.patch.object(wb_cn_sms, "load_device_token", return_value="ticket"), \
             mock.patch.object(wb_cn_sms, "session_for", return_value=login), \
             mock.patch.object(wb_cn_sms, "drop") as drop:
            result = self.route(proxy.Handler._route_accounts_login_sms_verify,
                                {"state": "live", "code": "123456"})
        self.assertEqual(login.code, "123456")
        self.assertEqual(self.pool.polled, ["live"])
        drop.assert_called_once_with("live")
        self.assertEqual(result[0], 200)
        self.assertEqual(result[1]["status"], "ok")


if __name__ == "__main__":
    unittest.main()
