#!/usr/bin/env python3
"""Connect to a UniFi UDM Pro Max (UniFi OS console) and configure it.

This module talks to the UniFi Network application that runs on UniFi OS
consoles such as the Dream Machine Pro / Pro Max. It supports two ways to
authenticate:

1. API key (recommended). Create one in the UniFi Network application under
   Settings -> Control Plane -> Integrations (or Settings -> System -> API).
   Requests use the official Integration API at
   ``/proxy/network/integration/v1`` with the ``X-API-KEY`` header.

2. Local account (username / password). Uses the UniFi OS login flow at
   ``/api/auth/login`` and the classic controller API proxied at
   ``/proxy/network/api``. This path is needed for configuration endpoints
   that the Integration API does not yet expose.

Both a small client library and a command line interface are provided. See
``README.md`` for setup and examples.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict, List, Optional

try:
    import requests
    from requests import Response, Session
except ImportError:  # pragma: no cover - dependency hint
    sys.stderr.write(
        "The 'requests' package is required. Install it with:\n"
        "    pip install -r requirements.txt\n"
    )
    raise


DEFAULT_SITE = "default"
DEFAULT_TIMEOUT = 30


class UniFiError(RuntimeError):
    """Raised when the controller returns an error or a request fails."""


class UDMClient:
    """A client for a UDM Pro Max / UniFi OS console.

    Parameters
    ----------
    host:
        Hostname or IP of the console, e.g. ``192.168.1.1`` or
        ``udm.example.com``. Do not include a scheme.
    api_key:
        API key for the Integration API. Mutually preferred over
        username/password when provided.
    username, password:
        Local account credentials for session (cookie) based auth.
    site:
        UniFi site name (the internal id, usually ``default``).
    verify_ssl:
        Verify the TLS certificate. UDM consoles ship with a self-signed
        certificate, so this defaults to ``False``. Set a CA bundle path or
        ``True`` if you have installed a trusted certificate.
    port:
        HTTPS port (default 443).
    timeout:
        Per-request timeout in seconds.
    """

    def __init__(
        self,
        host: str,
        api_key: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        site: str = DEFAULT_SITE,
        verify_ssl: bool = False,
        port: int = 443,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> None:
        if not host:
            raise ValueError("host is required")
        if not api_key and not (username and password):
            raise ValueError(
                "provide either api_key or both username and password"
            )

        self.host = host.replace("https://", "").replace("http://", "").rstrip("/")
        self.api_key = api_key
        self.username = username
        self.password = password
        self.site = site
        self.verify_ssl = verify_ssl
        self.port = port
        self.timeout = timeout

        self.base_url = f"https://{self.host}:{self.port}"
        self.session: Session = requests.Session()
        self.session.verify = verify_ssl
        self._csrf_token: Optional[str] = None
        self._logged_in = False

        if not verify_ssl:
            # Silence the noisy warning for the expected self-signed cert.
            try:
                import urllib3

                urllib3.disable_warnings(
                    urllib3.exceptions.InsecureRequestWarning
                )
            except Exception:  # pragma: no cover - best effort
                pass

    # -- Auth ---------------------------------------------------------------

    @property
    def use_api_key(self) -> bool:
        return bool(self.api_key)

    def login(self) -> None:
        """Establish a session.

        For API key auth this is a no-op verification call. For local
        account auth this performs the UniFi OS login and captures the CSRF
        token required for mutating requests.
        """
        if self.use_api_key:
            # Nothing to log in; validate the key with a cheap call.
            self.list_sites()
            self._logged_in = True
            return

        url = f"{self.base_url}/api/auth/login"
        resp = self.session.post(
            url,
            json={"username": self.username, "password": self.password},
            timeout=self.timeout,
        )
        if resp.status_code == 401:
            raise UniFiError("Login failed: invalid username or password")
        self._raise_for_status(resp, "login")

        # UniFi OS returns the CSRF token in a response header and/or the
        # TOKEN cookie. Capture whichever is present.
        self._csrf_token = (
            resp.headers.get("X-Updated-CSRF-Token")
            or resp.headers.get("X-CSRF-Token")
            or self._csrf_token
        )
        self._logged_in = True

    def logout(self) -> None:
        if self.use_api_key or not self._logged_in:
            return
        try:
            self.session.post(
                f"{self.base_url}/api/auth/logout", timeout=self.timeout
            )
        except requests.RequestException:
            pass
        finally:
            self._logged_in = False

    # -- Low level request helpers -----------------------------------------

    def _headers(self, mutating: bool) -> Dict[str, str]:
        headers = {"Accept": "application/json"}
        if self.use_api_key:
            headers["X-API-KEY"] = self.api_key or ""
        elif mutating and self._csrf_token:
            headers["X-CSRF-Token"] = self._csrf_token
        return headers

    def _request(
        self,
        method: str,
        path: str,
        *,
        json_body: Optional[Any] = None,
        params: Optional[Dict[str, Any]] = None,
    ) -> Any:
        mutating = method.upper() not in ("GET", "HEAD")
        if not self._logged_in and not self.use_api_key:
            self.login()

        url = f"{self.base_url}{path}"
        resp = self.session.request(
            method,
            url,
            json=json_body,
            params=params,
            headers=self._headers(mutating),
            timeout=self.timeout,
        )

        # A stale CSRF token surfaces as 401 on mutating calls; refresh once.
        if resp.status_code == 401 and not self.use_api_key and mutating:
            self.login()
            resp = self.session.request(
                method,
                url,
                json=json_body,
                params=params,
                headers=self._headers(mutating),
                timeout=self.timeout,
            )

        # Refresh the rolling CSRF token when the console rotates it.
        rotated = resp.headers.get("X-Updated-CSRF-Token")
        if rotated:
            self._csrf_token = rotated

        self._raise_for_status(resp, f"{method} {path}")
        if not resp.content:
            return None
        try:
            return resp.json()
        except ValueError:
            return resp.text

    @staticmethod
    def _raise_for_status(resp: Response, context: str) -> None:
        if resp.status_code < 400:
            return
        detail = ""
        try:
            body = resp.json()
            detail = body.get("message") or body.get("error") or json.dumps(body)
        except ValueError:
            detail = resp.text[:500]
        raise UniFiError(
            f"{context} failed: HTTP {resp.status_code} {detail}".strip()
        )

    # -- Integration API (API key) -----------------------------------------

    def _integration(self, path: str) -> str:
        return f"/proxy/network/integration/v1{path}"

    # -- Classic controller API (cookie auth) ------------------------------

    def _network(self, path: str) -> str:
        return f"/proxy/network/api/s/{self.site}{path}"

    # -- High level operations ---------------------------------------------

    def list_sites(self) -> List[Dict[str, Any]]:
        """List sites managed by the console."""
        if self.use_api_key:
            data = self._request("GET", self._integration("/sites"))
            return data.get("data", data) if isinstance(data, dict) else data
        data = self._request("GET", "/proxy/network/api/self/sites")
        return data.get("data", []) if isinstance(data, dict) else data

    def get_system_info(self) -> Dict[str, Any]:
        """Return console/controller system information."""
        data = self._request("GET", self._network("/stat/sysinfo"))
        items = data.get("data", []) if isinstance(data, dict) else data
        return items[0] if items else {}

    def list_devices(self) -> List[Dict[str, Any]]:
        """List UniFi devices adopted by this site (APs, switches, gateway)."""
        if self.use_api_key:
            data = self._request(
                "GET", self._integration(f"/sites/{self.site}/devices")
            )
            return data.get("data", data) if isinstance(data, dict) else data
        data = self._request("GET", self._network("/stat/device"))
        return data.get("data", []) if isinstance(data, dict) else data

    def list_clients(self) -> List[Dict[str, Any]]:
        """List active clients on the site."""
        data = self._request("GET", self._network("/stat/sta"))
        return data.get("data", []) if isinstance(data, dict) else data

    def list_wlans(self) -> List[Dict[str, Any]]:
        """List configured WLANs (Wi-Fi networks)."""
        data = self._request("GET", self._network("/rest/wlanconf"))
        return data.get("data", []) if isinstance(data, dict) else data

    def get_wlan(self, name: str) -> Optional[Dict[str, Any]]:
        """Find a WLAN configuration by its SSID/name."""
        for wlan in self.list_wlans():
            if wlan.get("name") == name:
                return wlan
        return None

    def set_wlan_enabled(self, wlan_id: str, enabled: bool) -> Dict[str, Any]:
        """Enable or disable a WLAN by its ``_id``."""
        path = self._network(f"/rest/wlanconf/{wlan_id}")
        data = self._request("PUT", path, json_body={"enabled": bool(enabled)})
        items = data.get("data", []) if isinstance(data, dict) else data
        return items[0] if items else {}

    def update_wlan(self, wlan_id: str, settings: Dict[str, Any]) -> Dict[str, Any]:
        """Update arbitrary fields of a WLAN configuration.

        ``settings`` is merged into the existing config server-side; pass only
        the keys you want to change, e.g. ``{"x_passphrase": "newsecret"}``.
        """
        path = self._network(f"/rest/wlanconf/{wlan_id}")
        data = self._request("PUT", path, json_body=settings)
        items = data.get("data", []) if isinstance(data, dict) else data
        return items[0] if items else {}

    def set_wlan_password(self, name: str, passphrase: str) -> Dict[str, Any]:
        """Change the passphrase for the WLAN with the given SSID."""
        wlan = self.get_wlan(name)
        if not wlan:
            raise UniFiError(f"No WLAN named {name!r} found")
        return self.update_wlan(wlan["_id"], {"x_passphrase": passphrase})

    def list_networks(self) -> List[Dict[str, Any]]:
        """List configured LAN/VLAN networks."""
        data = self._request("GET", self._network("/rest/networkconf"))
        return data.get("data", []) if isinstance(data, dict) else data

    def list_port_forwards(self) -> List[Dict[str, Any]]:
        """List port forwarding rules on the gateway."""
        data = self._request("GET", self._network("/rest/portforward"))
        return data.get("data", []) if isinstance(data, dict) else data

    def create_port_forward(
        self,
        name: str,
        fwd_ip: str,
        fwd_port: str,
        dst_port: str,
        proto: str = "tcp_udp",
        src: str = "any",
        enabled: bool = True,
    ) -> Dict[str, Any]:
        """Create a port forwarding rule on the UDM gateway."""
        rule = {
            "name": name,
            "enabled": enabled,
            "pfwd_interface": "wan",
            "fwd": fwd_ip,
            "fwd_port": str(fwd_port),
            "dst_port": str(dst_port),
            "proto": proto,
            "src": src,
            "log": False,
        }
        data = self._request(
            "POST", self._network("/rest/portforward"), json_body=rule
        )
        items = data.get("data", []) if isinstance(data, dict) else data
        return items[0] if items else {}

    def delete_port_forward(self, rule_id: str) -> None:
        """Delete a port forwarding rule by its ``_id``."""
        self._request("DELETE", self._network(f"/rest/portforward/{rule_id}"))

    def device_action(self, mac: str, action: str) -> Any:
        """Run a device management command.

        ``action`` is one of the controller ``devmgr`` commands such as
        ``restart``, ``adopt``, ``force-provision``, or ``set-locate``.
        """
        payload = {"cmd": action, "mac": mac.lower()}
        return self._request(
            "POST", self._network("/cmd/devmgr"), json_body=payload
        )

    def restart_device(self, mac: str) -> Any:
        """Restart an adopted device by MAC address."""
        return self.device_action(mac, "restart")

    # -- Context manager ----------------------------------------------------

    def __enter__(self) -> "UDMClient":
        self.login()
        return self

    def __exit__(self, *exc: Any) -> None:
        self.logout()


# -- CLI --------------------------------------------------------------------


def _client_from_args(args: argparse.Namespace) -> UDMClient:
    host = args.host or os.environ.get("UNIFI_HOST")
    api_key = args.api_key or os.environ.get("UNIFI_API_KEY")
    username = args.username or os.environ.get("UNIFI_USERNAME")
    password = args.password or os.environ.get("UNIFI_PASSWORD")
    site = args.site or os.environ.get("UNIFI_SITE", DEFAULT_SITE)

    if not host:
        raise SystemExit("Error: --host (or UNIFI_HOST) is required")
    if not api_key and not (username and password):
        raise SystemExit(
            "Error: provide --api-key (UNIFI_API_KEY) or "
            "--username/--password (UNIFI_USERNAME/UNIFI_PASSWORD)"
        )

    return UDMClient(
        host=host,
        api_key=api_key,
        username=username,
        password=password,
        site=site,
        verify_ssl=args.verify_ssl,
        port=args.port,
    )


def _print(obj: Any) -> None:
    print(json.dumps(obj, indent=2, sort_keys=True, default=str))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Connect to a UDM Pro Max and configure it via the "
        "UniFi Network application API.",
    )
    parser.add_argument("--host", help="Console hostname or IP (UNIFI_HOST)")
    parser.add_argument("--api-key", help="Integration API key (UNIFI_API_KEY)")
    parser.add_argument("--username", help="Local account (UNIFI_USERNAME)")
    parser.add_argument("--password", help="Local account (UNIFI_PASSWORD)")
    parser.add_argument(
        "--site", help="Site id, default 'default' (UNIFI_SITE)"
    )
    parser.add_argument(
        "--port", type=int, default=443, help="HTTPS port (default 443)"
    )
    parser.add_argument(
        "--verify-ssl",
        action="store_true",
        help="Verify TLS cert (off by default for self-signed consoles)",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("sites", help="List sites")
    sub.add_parser("info", help="Show controller system info")
    sub.add_parser("devices", help="List adopted devices")
    sub.add_parser("clients", help="List active clients")
    sub.add_parser("wlans", help="List Wi-Fi networks")
    sub.add_parser("networks", help="List LAN/VLAN networks")
    sub.add_parser("port-forwards", help="List port forwarding rules")

    p_wlan = sub.add_parser("set-wlan", help="Enable/disable a WLAN by name")
    p_wlan.add_argument("name", help="SSID / WLAN name")
    p_wlan.add_argument(
        "state", choices=["on", "off"], help="Turn the WLAN on or off"
    )

    p_pass = sub.add_parser("set-wlan-password", help="Change a WLAN passphrase")
    p_pass.add_argument("name", help="SSID / WLAN name")
    p_pass.add_argument("passphrase", help="New passphrase")

    p_restart = sub.add_parser("restart-device", help="Restart a device by MAC")
    p_restart.add_argument("mac", help="Device MAC address")

    return parser


def run_command(args: argparse.Namespace) -> None:
    client = _client_from_args(args)
    with client:
        if args.command == "sites":
            _print(client.list_sites())
        elif args.command == "info":
            _print(client.get_system_info())
        elif args.command == "devices":
            _print(client.list_devices())
        elif args.command == "clients":
            _print(client.list_clients())
        elif args.command == "wlans":
            _print(client.list_wlans())
        elif args.command == "networks":
            _print(client.list_networks())
        elif args.command == "port-forwards":
            _print(client.list_port_forwards())
        elif args.command == "set-wlan":
            wlan = client.get_wlan(args.name)
            if not wlan:
                raise SystemExit(f"No WLAN named {args.name!r} found")
            _print(client.set_wlan_enabled(wlan["_id"], args.state == "on"))
        elif args.command == "set-wlan-password":
            _print(client.set_wlan_password(args.name, args.passphrase))
        elif args.command == "restart-device":
            _print(client.restart_device(args.mac))
        else:  # pragma: no cover - argparse enforces choices
            raise SystemExit(f"Unknown command: {args.command}")


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        run_command(args)
    except UniFiError as exc:
        sys.stderr.write(f"Error: {exc}\n")
        return 1
    except requests.RequestException as exc:
        sys.stderr.write(f"Connection error: {exc}\n")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
