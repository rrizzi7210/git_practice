#!/usr/bin/env python3
"""Live smoke test against a REAL (non-production) UDM.

Unlike ``test_unifi_udm.py`` (which mocks everything and needs no network),
this script talks to an actual console. Run it from a machine on the SAME
network as the UDM -- a cloud/CI runner cannot reach a LAN address.

Safety model
------------
- Read-only by default: it only lists sites/devices/networks and prints them.
- The write test is opt-in via ``--write`` and is self-cleaning: it creates a
  throwaway VLAN with a deliberately unusual id/subnet, verifies it appears,
  then deletes it. Nothing is left behind on success.
- ``--keep`` leaves the test VLAN in place (for manual inspection); otherwise
  cleanup runs even if verification fails.

Never point ``--write`` at a production console.

Usage
-----
    export UNIFI_HOST=192.168.1.1
    export UNIFI_API_KEY=...            # read-only checks
    # or, for the write test:
    export UNIFI_USERNAME=admin
    export UNIFI_PASSWORD=...

    python live_smoke_test.py                 # read-only
    python live_smoke_test.py --write         # create+verify+delete a VLAN
    python live_smoke_test.py --write --vlan-id 4093 --subnet 10.253.253.1/24
"""

from __future__ import annotations

import argparse
import os
import sys

from unifi_udm import UDMClient, UniFiError


def _ok(msg: str) -> None:
    print(f"  \033[32mPASS\033[0m {msg}")


def _fail(msg: str) -> None:
    print(f"  \033[31mFAIL\033[0m {msg}")


def _info(msg: str) -> None:
    print(f"  ->   {msg}")


def read_only_checks(client: UDMClient) -> bool:
    print("\n== Read-only checks ==")
    passed = True

    try:
        sites = client.list_sites()
        _ok(f"list_sites returned {len(sites)} site(s)")
    except UniFiError as exc:
        _fail(f"list_sites: {exc}")
        return False  # nothing else will work

    try:
        devices = client.list_devices()
        _ok(f"list_devices returned {len(devices)} device(s)")
        for d in devices[:5]:
            _info(
                f"{d.get('name') or d.get('model', '?')} "
                f"[{d.get('model', '?')}] {d.get('ip', '')}".strip()
            )
    except UniFiError as exc:
        _fail(f"list_devices: {exc}")
        passed = False

    try:
        nets = client.list_networks()
        _ok(f"list_networks returned {len(nets)} network(s)")
        for n in nets[:10]:
            vlan = n.get("vlan")
            tag = f" vlan={vlan}" if vlan else ""
            _info(f"{n.get('name', '?')} {n.get('ip_subnet', '')}{tag}".rstrip())
    except UniFiError as exc:
        _fail(f"list_networks: {exc}")
        passed = False

    return passed


def vlan_write_check(
    client: UDMClient, name: str, vlan_id: int, subnet: str, keep: bool
) -> bool:
    print("\n== VLAN create/verify/delete ==")

    existing = client.get_network(name)
    if existing:
        _fail(f"a network named {name!r} already exists; choose another --name")
        return False
    if any(n.get("vlan") == vlan_id for n in client.list_networks()):
        _fail(f"VLAN id {vlan_id} is already in use; choose another --vlan-id")
        return False

    created_id = None
    try:
        created = client.create_vlan(name=name, vlan_id=vlan_id, subnet=subnet)
        created_id = created.get("_id")
        if not created_id:
            _fail(f"create_vlan returned no _id: {created}")
            return False
        _ok(f"created VLAN {name!r} id={vlan_id} subnet={subnet} (_id={created_id})")

        found = client.get_network(name)
        if found and found.get("vlan") == vlan_id and found.get("_id") == created_id:
            _ok("verified: new VLAN is listed with the expected id")
        else:
            _fail(f"verification mismatch: {found}")
            return False

        if keep:
            _info(f"--keep set; leaving VLAN {name!r} in place (_id={created_id})")
            return True
        return True
    except (UniFiError, ValueError) as exc:
        _fail(f"write test: {exc}")
        return False
    finally:
        if created_id and not keep:
            try:
                client.delete_network(created_id)
                _ok(f"cleaned up: deleted VLAN _id={created_id}")
                if client.get_network(name):
                    _fail("cleanup verification: VLAN still present after delete")
                else:
                    _ok("verified: VLAN no longer listed")
            except UniFiError as exc:
                _fail(f"CLEANUP FAILED, delete manually (_id={created_id}): {exc}")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--host", help="Console host/IP (UNIFI_HOST)")
    p.add_argument("--api-key", help="API key (UNIFI_API_KEY)")
    p.add_argument("--username", help="Local account (UNIFI_USERNAME)")
    p.add_argument("--password", help="Local account (UNIFI_PASSWORD)")
    p.add_argument("--site", default=os.environ.get("UNIFI_SITE", "default"))
    p.add_argument("--port", type=int, default=443)
    p.add_argument("--verify-ssl", action="store_true")
    p.add_argument(
        "--write",
        action="store_true",
        help="Run the create/verify/delete VLAN test (needs a local account)",
    )
    p.add_argument("--name", default="ZZ-smoke-test", help="Throwaway VLAN name")
    p.add_argument(
        "--vlan-id", type=int, default=4094, help="Throwaway VLAN id (default 4094)"
    )
    p.add_argument(
        "--subnet",
        default="10.254.254.1/24",
        help="Throwaway gateway CIDR (default 10.254.254.1/24)",
    )
    p.add_argument("--keep", action="store_true", help="Do not delete the test VLAN")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    host = args.host or os.environ.get("UNIFI_HOST")
    api_key = args.api_key or os.environ.get("UNIFI_API_KEY")
    username = args.username or os.environ.get("UNIFI_USERNAME")
    password = args.password or os.environ.get("UNIFI_PASSWORD")

    if not host:
        print("Set --host or UNIFI_HOST", file=sys.stderr)
        return 2
    if not api_key and not (username and password):
        print("Set --api-key or --username/--password", file=sys.stderr)
        return 2
    if args.write and not (username and password):
        print(
            "The --write test needs a local account "
            "(UNIFI_USERNAME/UNIFI_PASSWORD); the API key is read-only here.",
            file=sys.stderr,
        )
        return 2

    print(f"Target console: https://{host}:{args.port} (site={args.site})")
    print("Auth: " + ("API key" if api_key and not args.write else "local account"))

    client = UDMClient(
        host=host,
        api_key=None if args.write else api_key,
        username=username,
        password=password,
        site=args.site,
        verify_ssl=args.verify_ssl,
        port=args.port,
    )

    ok = True
    try:
        with client:
            ok &= read_only_checks(client)
            if args.write:
                ok &= vlan_write_check(
                    client, args.name, args.vlan_id, args.subnet, args.keep
                )
    except UniFiError as exc:
        print(f"\nFatal: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:  # noqa: BLE001 - surface connection issues plainly
        print(f"\nConnection error: {exc}", file=sys.stderr)
        print(
            "If this is a timeout, confirm you are on the same LAN as the UDM.",
            file=sys.stderr,
        )
        return 2

    print("\n" + ("All checks passed." if ok else "Some checks FAILED."))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
