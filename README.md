# unifi-udm

A small Python client and CLI to connect to a **UniFi Dream Machine Pro Max**
(or any UniFi OS console) and configure it through the UniFi Network
application API.

The UDM Pro Max runs the UniFi Network application locally, so you point this
tool at the console itself — there is no cloud round-trip required.

## Features

- Two authentication modes:
  - **API key** (recommended) via the official Integration API.
  - **Local account** (username / password) for configuration endpoints not
    yet covered by the Integration API, including CSRF handling.
- List sites, devices, clients, Wi-Fi networks, LAN/VLAN networks and port
  forwards.
- Enable/disable a WLAN, change a WLAN passphrase, create/delete port
  forwards, and restart adopted devices.
- Usable both as a library (`UDMClient`) and as a command line tool.

## Install

```bash
pip install -r requirements.txt
```

Requires Python 3.8+.

## Authentication

### API key (recommended)

1. Open the UniFi Network application on your UDM Pro Max.
2. Go to **Settings → Control Plane → Integrations** (labelled **API** on some
   versions) and create an API key.
3. Export it:

   ```bash
   export UNIFI_HOST=192.168.1.1
   export UNIFI_API_KEY=your-key-here
   ```

### Local account

Some configuration endpoints (WLAN edits, port forwards, device restarts) are
exposed through the classic controller API, which uses a logged-in session.
Create a **local** admin account on the console (not a Ubiquiti cloud SSO
account, which cannot log in locally) and export:

```bash
export UNIFI_HOST=192.168.1.1
export UNIFI_USERNAME=admin
export UNIFI_PASSWORD=your-password
```

You can also pass any of these on the command line (`--host`, `--api-key`,
`--username`, `--password`). See `.env.example`.

> The console ships with a self-signed TLS certificate, so certificate
> verification is **off** by default. Pass `--verify-ssl` once you have
> installed a trusted certificate.

## CLI usage

```bash
# Read-only
python unifi_udm.py sites
python unifi_udm.py info
python unifi_udm.py devices
python unifi_udm.py clients
python unifi_udm.py wlans
python unifi_udm.py networks
python unifi_udm.py port-forwards

# Configuration (requires a local account)
python unifi_udm.py set-wlan "Guest WiFi" off
python unifi_udm.py set-wlan-password "My WiFi" 'new-super-secret'
python unifi_udm.py restart-device aa:bb:cc:dd:ee:ff
```

## Library usage

```python
from unifi_udm import UDMClient

with UDMClient(host="192.168.1.1", username="admin", password="secret") as udm:
    for device in udm.list_devices():
        print(device.get("name"), device.get("model"), device.get("ip"))

    # Disable the guest WLAN
    wlan = udm.get_wlan("Guest WiFi")
    if wlan:
        udm.set_wlan_enabled(wlan["_id"], False)

    # Add a port forward
    udm.create_port_forward(
        name="Web",
        fwd_ip="192.168.1.50",
        fwd_port=8080,
        dst_port=80,
        proto="tcp",
    )
```

## Testing

The test suite mocks the HTTP layer entirely — no network or real console is
needed:

```bash
python -m unittest test_unifi_udm -v
```

It covers auth (API key and username/password), CSRF capture/rotation and
stale-token re-login, request/response parsing, error handling, each
high-level operation's request payload, and the CLI wiring.

## Notes

- The Integration API is the supported, stable interface. The classic
  controller endpoints (`/proxy/network/api/...`) are unofficial and may
  change between UniFi Network releases; they are used here only where the
  Integration API does not yet provide equivalent configuration.
- Tested against the UniFi Network application API surface used by UniFi OS
  consoles. Behaviour can vary with firmware version.

## Disclaimer

This project is not affiliated with or endorsed by Ubiquiti Inc. UniFi, UDM
and Dream Machine are trademarks of Ubiquiti Inc.
