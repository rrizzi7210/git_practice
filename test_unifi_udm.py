#!/usr/bin/env python3
"""Unit tests for unifi_udm with a fully mocked HTTP layer.

No network access is performed. Every test installs a fake ``requests``
session on the ``UDMClient`` (or patches the module-level ``requests``) so the
client's request-building, auth, CSRF handling and response parsing can be
exercised in isolation.
"""

from __future__ import annotations

import contextlib
import io
import unittest
from typing import Any, Dict, List, Optional, Tuple
from unittest import mock

import unifi_udm
from unifi_udm import UDMClient, UniFiError


class FakeResponse:
    """Minimal stand-in for ``requests.Response``."""

    def __init__(
        self,
        status_code: int = 200,
        json_data: Any = None,
        headers: Optional[Dict[str, str]] = None,
        text: str = "",
        raise_on_json: bool = False,
    ) -> None:
        self.status_code = status_code
        self._json_data = json_data
        self.headers = headers or {}
        self.text = text
        self._raise_on_json = raise_on_json

    @property
    def content(self) -> bytes:
        if self._json_data is None and not self.text:
            return b""
        return b"x"

    def json(self) -> Any:
        if self._raise_on_json or self._json_data is None:
            raise ValueError("no json")
        return self._json_data


class FakeSession:
    """Records calls and returns queued responses."""

    def __init__(self) -> None:
        self.verify: Any = None
        self.calls: List[Dict[str, Any]] = []
        # Map of (METHOD, path-suffix) -> FakeResponse or list of them.
        self._routes: Dict[Tuple[str, str], Any] = {}
        self.default_response = FakeResponse(200, {"data": []})

    def route(self, method: str, path_suffix: str, response: Any) -> None:
        self._routes[(method.upper(), path_suffix)] = response

    def _lookup(self, method: str, url: str) -> FakeResponse:
        for (m, suffix), resp in self._routes.items():
            if m == method.upper() and url.endswith(suffix):
                if isinstance(resp, list):
                    # Pop successive responses to simulate state changes.
                    return resp.pop(0) if len(resp) > 1 else resp[0]
                return resp
        return self.default_response

    def request(
        self,
        method: str,
        url: str,
        json: Any = None,
        params: Any = None,
        headers: Any = None,
        timeout: Any = None,
    ) -> FakeResponse:
        self.calls.append(
            {
                "method": method,
                "url": url,
                "json": json,
                "params": params,
                "headers": headers or {},
            }
        )
        return self._lookup(method, url)

    def post(
        self,
        url: str,
        json: Any = None,
        headers: Any = None,
        timeout: Any = None,
    ) -> FakeResponse:
        self.calls.append(
            {"method": "POST", "url": url, "json": json, "headers": headers or {}}
        )
        return self._lookup("POST", url)


def make_client(**kwargs: Any) -> Tuple[UDMClient, FakeSession]:
    """Build a client with a fake session installed."""
    defaults: Dict[str, Any] = dict(host="udm.test", api_key="KEY123")
    defaults.update(kwargs)
    client = UDMClient(**defaults)
    fake = FakeSession()
    client.session = fake  # type: ignore[assignment]
    return client, fake


class ConstructorTests(unittest.TestCase):
    def test_requires_host(self) -> None:
        with self.assertRaises(ValueError):
            UDMClient(host="", api_key="k")

    def test_requires_some_credentials(self) -> None:
        with self.assertRaises(ValueError):
            UDMClient(host="udm.test")

    def test_password_without_username_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            UDMClient(host="udm.test", password="p")

    def test_strips_scheme_and_builds_base_url(self) -> None:
        client, _ = make_client(host="https://udm.test/", port=8443)
        self.assertEqual(client.host, "udm.test")
        self.assertEqual(client.base_url, "https://udm.test:8443")

    def test_use_api_key_property(self) -> None:
        api_client, _ = make_client()
        self.assertTrue(api_client.use_api_key)
        pw_client, _ = make_client(api_key=None, username="u", password="p")
        self.assertFalse(pw_client.use_api_key)


class HeaderTests(unittest.TestCase):
    def test_api_key_header_present(self) -> None:
        client, _ = make_client()
        headers = client._headers(mutating=True)
        self.assertEqual(headers["X-API-KEY"], "KEY123")
        self.assertNotIn("X-CSRF-Token", headers)

    def test_csrf_header_only_on_mutating_calls(self) -> None:
        client, _ = make_client(api_key=None, username="u", password="p")
        client._csrf_token = "tok"
        self.assertNotIn("X-CSRF-Token", client._headers(mutating=False))
        self.assertEqual(client._headers(mutating=True)["X-CSRF-Token"], "tok")


class ApiKeyLoginTests(unittest.TestCase):
    def test_login_validates_key_via_sites(self) -> None:
        client, fake = make_client()
        fake.route("GET", "/integration/v1/sites", FakeResponse(200, {"data": []}))
        client.login()
        self.assertTrue(client._logged_in)
        # Only the validation GET was made; no /api/auth/login POST.
        self.assertTrue(all(c["method"] == "GET" for c in fake.calls))

    def test_api_key_requests_send_key_header(self) -> None:
        client, fake = make_client()
        fake.route(
            "GET",
            "/integration/v1/sites",
            FakeResponse(200, {"data": [{"name": "default"}]}),
        )
        client.list_sites()
        self.assertEqual(fake.calls[-1]["headers"]["X-API-KEY"], "KEY123")


class PasswordLoginTests(unittest.TestCase):
    def _client(self) -> Tuple[UDMClient, FakeSession]:
        return make_client(api_key=None, username="admin", password="secret")

    def test_login_captures_csrf_token(self) -> None:
        client, fake = self._client()
        fake.route(
            "POST",
            "/api/auth/login",
            FakeResponse(200, {"ok": True}, headers={"X-Updated-CSRF-Token": "abc"}),
        )
        client.login()
        self.assertTrue(client._logged_in)
        self.assertEqual(client._csrf_token, "abc")
        login_call = fake.calls[0]
        self.assertTrue(login_call["url"].endswith("/api/auth/login"))
        self.assertEqual(login_call["json"], {"username": "admin", "password": "secret"})

    def test_login_bad_credentials_raises(self) -> None:
        client, fake = self._client()
        fake.route("POST", "/api/auth/login", FakeResponse(401, {"message": "no"}))
        with self.assertRaises(UniFiError):
            client.login()

    def test_lazy_login_before_first_request(self) -> None:
        client, fake = self._client()
        fake.route(
            "POST", "/api/auth/login", FakeResponse(200, {}, headers={"X-Updated-CSRF-Token": "t"})
        )
        fake.route("GET", "/stat/device", FakeResponse(200, {"data": []}))
        client.list_devices()
        # First call is the login, then the device fetch.
        self.assertTrue(fake.calls[0]["url"].endswith("/api/auth/login"))
        self.assertTrue(fake.calls[1]["url"].endswith("/stat/device"))

    def test_stale_csrf_triggers_relogin_on_mutating_call(self) -> None:
        client, fake = self._client()
        client._logged_in = True
        client._csrf_token = "old"
        # First PUT 401s, re-login, then the retried PUT succeeds.
        fake.route(
            "PUT",
            "/rest/wlanconf/W1",
            [
                FakeResponse(401, {"message": "csrf"}),
                FakeResponse(200, {"data": [{"_id": "W1", "enabled": False}]}),
            ],
        )
        fake.route(
            "POST", "/api/auth/login", FakeResponse(200, {}, headers={"X-Updated-CSRF-Token": "new"})
        )
        result = client.set_wlan_enabled("W1", False)
        self.assertEqual(result["_id"], "W1")
        # A re-login POST happened between the two PUTs.
        methods = [c["method"] for c in fake.calls]
        self.assertIn("POST", methods)
        self.assertEqual(client._csrf_token, "new")

    def test_rotated_csrf_token_is_captured(self) -> None:
        client, fake = self._client()
        client._logged_in = True
        client._csrf_token = "old"
        fake.route(
            "GET",
            "/stat/device",
            FakeResponse(200, {"data": []}, headers={"X-Updated-CSRF-Token": "rotated"}),
        )
        client.list_devices()
        self.assertEqual(client._csrf_token, "rotated")


class ErrorHandlingTests(unittest.TestCase):
    def test_http_error_with_json_message(self) -> None:
        client, fake = make_client()
        fake.route("GET", "/integration/v1/sites", FakeResponse(403, {"message": "denied"}))
        with self.assertRaises(UniFiError) as ctx:
            client.list_sites()
        self.assertIn("denied", str(ctx.exception))
        self.assertIn("403", str(ctx.exception))

    def test_http_error_with_text_body(self) -> None:
        client, fake = make_client()
        fake.route(
            "GET",
            "/integration/v1/sites",
            FakeResponse(500, json_data=None, text="boom", raise_on_json=True),
        )
        with self.assertRaises(UniFiError) as ctx:
            client.list_sites()
        self.assertIn("boom", str(ctx.exception))

    def test_empty_body_returns_none(self) -> None:
        client, fake = make_client()
        fake.route("DELETE", "/rest/portforward/P1", FakeResponse(200, json_data=None))
        # delete_port_forward returns None and must not raise.
        self.assertIsNone(client.delete_port_forward("P1"))


class OperationTests(unittest.TestCase):
    def test_list_devices_unwraps_data(self) -> None:
        client, fake = make_client()
        fake.route(
            "GET",
            "/integration/v1/sites/default/devices",
            FakeResponse(200, {"data": [{"name": "AP1"}, {"name": "SW1"}]}),
        )
        devices = client.list_devices()
        self.assertEqual([d["name"] for d in devices], ["AP1", "SW1"])

    def test_get_system_info_returns_first_item(self) -> None:
        client, fake = make_client(api_key=None, username="u", password="p")
        client._logged_in = True
        fake.route("GET", "/stat/sysinfo", FakeResponse(200, {"data": [{"version": "9.0"}]}))
        info = client.get_system_info()
        self.assertEqual(info["version"], "9.0")

    def test_get_system_info_empty(self) -> None:
        client, fake = make_client(api_key=None, username="u", password="p")
        client._logged_in = True
        fake.route("GET", "/stat/sysinfo", FakeResponse(200, {"data": []}))
        self.assertEqual(client.get_system_info(), {})

    def test_get_wlan_by_name(self) -> None:
        client, fake = make_client(api_key=None, username="u", password="p")
        client._logged_in = True
        fake.route(
            "GET",
            "/rest/wlanconf",
            FakeResponse(200, {"data": [{"_id": "W1", "name": "Guest"}, {"_id": "W2", "name": "Main"}]}),
        )
        self.assertEqual(client.get_wlan("Main")["_id"], "W2")
        # Re-route empty to prove missing returns None.
        fake.route("GET", "/rest/wlanconf", FakeResponse(200, {"data": []}))
        self.assertIsNone(client.get_wlan("Nope"))

    def test_set_wlan_password_puts_passphrase(self) -> None:
        client, fake = make_client(api_key=None, username="u", password="p")
        client._logged_in = True
        fake.route(
            "GET",
            "/rest/wlanconf",
            FakeResponse(200, {"data": [{"_id": "W1", "name": "Main"}]}),
        )
        fake.route("PUT", "/rest/wlanconf/W1", FakeResponse(200, {"data": [{"_id": "W1"}]}))
        client.set_wlan_password("Main", "hunter2")
        put_call = [c for c in fake.calls if c["method"] == "PUT"][-1]
        self.assertEqual(put_call["json"], {"x_passphrase": "hunter2"})

    def test_set_wlan_password_missing_wlan_raises(self) -> None:
        client, fake = make_client(api_key=None, username="u", password="p")
        client._logged_in = True
        fake.route("GET", "/rest/wlanconf", FakeResponse(200, {"data": []}))
        with self.assertRaises(UniFiError):
            client.set_wlan_password("Ghost", "x")

    def test_create_port_forward_payload(self) -> None:
        client, fake = make_client(api_key=None, username="u", password="p")
        client._logged_in = True
        fake.route("POST", "/rest/portforward", FakeResponse(200, {"data": [{"_id": "P1"}]}))
        client.create_port_forward(
            name="Web", fwd_ip="10.0.0.5", fwd_port=8080, dst_port=80, proto="tcp"
        )
        call = [c for c in fake.calls if c["method"] == "POST"][-1]
        body = call["json"]
        self.assertEqual(body["name"], "Web")
        self.assertEqual(body["fwd"], "10.0.0.5")
        self.assertEqual(body["fwd_port"], "8080")  # coerced to str
        self.assertEqual(body["dst_port"], "80")
        self.assertEqual(body["proto"], "tcp")
        self.assertTrue(body["enabled"])

    def test_restart_device_sends_lowercased_mac_command(self) -> None:
        client, fake = make_client(api_key=None, username="u", password="p")
        client._logged_in = True
        fake.route("POST", "/cmd/devmgr", FakeResponse(200, {"data": []}))
        client.restart_device("AA:BB:CC:DD:EE:FF")
        call = [c for c in fake.calls if c["method"] == "POST"][-1]
        self.assertEqual(call["json"], {"cmd": "restart", "mac": "aa:bb:cc:dd:ee:ff"})

    def test_network_path_uses_site(self) -> None:
        client, _ = make_client(api_key=None, username="u", password="p", site="office")
        self.assertEqual(client._network("/stat/device"), "/proxy/network/api/s/office/stat/device")


class ContextManagerTests(unittest.TestCase):
    def test_context_manager_logs_in_and_out(self) -> None:
        client, fake = make_client(api_key=None, username="u", password="p")
        fake.route(
            "POST", "/api/auth/login", FakeResponse(200, {}, headers={"X-Updated-CSRF-Token": "t"})
        )
        fake.route("POST", "/api/auth/logout", FakeResponse(200, {}))
        with client as c:
            self.assertTrue(c._logged_in)
        self.assertFalse(client._logged_in)
        urls = [c["url"] for c in fake.calls]
        self.assertTrue(any(u.endswith("/api/auth/login") for u in urls))
        self.assertTrue(any(u.endswith("/api/auth/logout") for u in urls))


class CliTests(unittest.TestCase):
    def test_client_from_args_reads_env(self) -> None:
        parser = unifi_udm.build_parser()
        args = parser.parse_args(["devices"])
        env = {"UNIFI_HOST": "udm.env", "UNIFI_API_KEY": "envkey"}
        with mock.patch.dict(unifi_udm.os.environ, env, clear=False):
            client = unifi_udm._client_from_args(args)
        self.assertEqual(client.host, "udm.env")
        self.assertEqual(client.api_key, "envkey")

    def test_client_from_args_missing_host_exits(self) -> None:
        parser = unifi_udm.build_parser()
        args = parser.parse_args(["devices"])
        clean = {k: v for k, v in unifi_udm.os.environ.items() if not k.startswith("UNIFI_")}
        with mock.patch.dict(unifi_udm.os.environ, clean, clear=True):
            with self.assertRaises(SystemExit):
                unifi_udm._client_from_args(args)

    def test_run_command_devices(self) -> None:
        args = unifi_udm.build_parser().parse_args(
            ["--host", "udm.test", "--api-key", "k", "devices"]
        )
        fake_client = mock.MagicMock()
        fake_client.__enter__ = mock.MagicMock(return_value=fake_client)
        fake_client.__exit__ = mock.MagicMock(return_value=False)
        fake_client.list_devices.return_value = [{"name": "AP"}]
        with mock.patch.object(unifi_udm, "_client_from_args", return_value=fake_client):
            with contextlib.redirect_stdout(io.StringIO()):
                unifi_udm.run_command(args)
        fake_client.list_devices.assert_called_once()

    def test_main_handles_unifi_error(self) -> None:
        args = ["--host", "udm.test", "--api-key", "k", "devices"]
        with mock.patch.object(unifi_udm, "run_command", side_effect=UniFiError("boom")):
            with contextlib.redirect_stderr(io.StringIO()):
                rc = unifi_udm.main(args)
        self.assertEqual(rc, 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
