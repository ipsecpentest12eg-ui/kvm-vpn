# KVM over VPN

Share mouse and keyboard between two Windows PCs over Surfshark (or any TCP-routable network).

## Setup

```
pip install -r requirements.txt
```

Do this on BOTH PCs.

## Find your Surfshark IP

On the SERVER PC, run in cmd:

```
ipconfig | findstr 10.
```

Look for an IP like `10.14.x.x` — that is the VPN IP the client will connect to.

## Run

**PC 1 — has the physical keyboard/mouse (SERVER):**

```
python kvm_server.py
```

Optional flags:
```
python kvm_server.py --port 9876 --switch-edge right --switch-threshold 3
```

**PC 2 — will receive input (CLIENT):**

```
python kvm_client.py --host 10.14.x.x
```

Replace `10.14.x.x` with the server's Surfshark IP.

Optional flags:
```
python kvm_client.py --host 10.14.x.x --port 9876
```

## How to switch between PCs

- Move cursor to the **right edge** of the server screen → input switches to client PC
- Move cursor back to the **left edge** → input returns to server PC

## Firewall

On the SERVER PC, allow port 9876 TCP inbound:

```
netsh advfirewall firewall add rule name="KVM VPN" dir=in action=allow protocol=TCP localport=9876
```

## Notes

- Server and client must both have Surfshark connected
- The server IP must be the Surfshark VPN IP (10.14.x.x), not the LAN IP
- Clipboard sync: works automatically when you copy text on the server while in remote mode
- Exit either script with Ctrl+C
