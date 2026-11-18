#!/usr/bin/env python3
"""Automatically select Npcap adapters for PROFINET DCP over RustDesk.

Bundled beside rustdesk.exe with PyInstaller; carries only read-only DCP
Identify over the authenticated RustDesk TCP tunnel (dcp_bridge.py).
"""
from __future__ import annotations

import argparse
import contextlib
import json
import os
import socket
import subprocess
import sys
import threading
import time
from dataclasses import dataclass

from dcp_bridge import (
    Npcap, PcapHandle, PendingXids, FramedSocket,
    REQUEST_MESSAGE, RESPONSE_MESSAGE, is_identify_request,
    is_identify_response, parse_dcp, parse_mac, iface_name,
    rewrite_destination, capture_worker, serve_remote,
)


@dataclass(frozen=True)
class Adapter:
    guid: str
    mac: bytes
    name: str
    ipv4: tuple[str, ...] = ()


def parse_adapters(text: str) -> list[Adapter]:
    raw = json.loads(text)
    raw = raw if isinstance(raw, list) else [raw]
    adapters = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        try:
            guid = str(item["InterfaceGuid"])
            mac = parse_mac(str(item["MacAddress"]))
            iface_name(guid)
        except (KeyError, ValueError, TypeError, argparse.ArgumentTypeError):
            continue
        addresses = item.get("IPv4", []) or []
        if isinstance(addresses, str):
            addresses = [addresses]
        adapters.append(Adapter(guid, mac, str(item.get("Name", guid)), tuple(addresses)))
    return adapters


def windows_adapters() -> list[Adapter]:
    if os.name != "nt":
        raise RuntimeError("Automatic Npcap adapter discovery requires Windows")
    script = (
        "Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | "
        "ForEach-Object { $a=$_; $ips=@(Get-NetIPAddress -InterfaceIndex "
        "$a.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | "
        "Select-Object -ExpandProperty IPAddress); "
        "[PSCustomObject]@{ Name=$a.Name; InterfaceGuid=$a.InterfaceGuid.ToString(); "
        "MacAddress=$a.MacAddress; IPv4=$ips } } | ConvertTo-Json -Compress -Depth 3"
    )
    output = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
        check=True, capture_output=True, text=True, timeout=20,
    )
    if not output.stdout.strip():
        raise RuntimeError("No active Windows adapters found")
    adapters = parse_adapters(output.stdout)
    if not adapters:
        raise RuntimeError("No valid Windows network adapter MAC addresses found")
    return adapters


def select_remote_adapter(adapters: list[Adapter], source_ip: str | None,
                          override_guid: str = "") -> Adapter:
    if override_guid:
        match = [a for a in adapters if iface_name(a.guid) == iface_name(override_guid)]
        if len(match) == 1:
            return match[0]
        raise RuntimeError("RUSTDESK_DCP_REMOTE_GUID does not identify an active adapter")
    match = [a for a in adapters if source_ip and source_ip in a.ipv4]
    if len(match) == 1:
        return match[0]
    if len(adapters) == 1:
        return adapters[0]
    raise RuntimeError(
        "Cannot unambiguously select the PLC-side NIC. "
        "Set RUSTDESK_DCP_REMOTE_GUID to its Get-NetAdapter InterfaceGuid"
    )


def local_ip_for_target(target: str) -> str | None:
    if not target or target.lower() in ("localhost", "127.0.0.1"):
        return None
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.connect((target, 102))  # Route selection only; no packet sent.
        return sock.getsockname()[0]


def connect_local_tunnel(port: int, timeout_seconds: float = 20.0) -> socket.socket:
    deadline = time.monotonic() + timeout_seconds
    while True:
        try:
            sock = socket.create_connection(("127.0.0.1", port), timeout=2)
            sock.settimeout(None)
            return sock
        except OSError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.25)


def run_local_auto(port: int, *, debug: bool = False) -> None:
    adapters = windows_adapters()
    print(f"[local-auto] Monitoring {len(adapters)} active adapters", flush=True)
    with connect_local_tunnel(port) as sock:
        link = FramedSocket(sock)
        api = Npcap()
        pending = PendingXids()
        stop = threading.Event()
        active: dict[bytes, PcapHandle] = {}
        workers: list[threading.Thread] = []
        with contextlib.ExitStack() as stack:
            for adapter in adapters:
                try:
                    capture = stack.enter_context(api.open(iface_name(adapter.guid)))
                    inject = stack.enter_context(
                        api.open(iface_name(adapter.guid), incoming_inject=True)
                    )
                    capture.filter_dcp()
                except (OSError, RuntimeError) as exc:
                    print(f"[local-auto] Skipping {adapter.name}: {exc}", flush=True)
                    continue
                active[adapter.mac] = inject

                def on_request(frame: bytes, nic: Adapter = adapter) -> None:
                    if not is_identify_request(frame, nic.mac):
                        return
                    header = parse_dcp(frame)
                    if header is None:
                        return
                    pending.add(header.xid, nic.mac)
                    link.send(REQUEST_MESSAGE, frame)
                    print(
                        f"[local-auto] Identify from {nic.name}, XID={header.xid.hex()}",
                        flush=True,
                    )

                worker = threading.Thread(
                    target=capture_worker, args=(capture, stop, on_request), daemon=True
                )
                worker.start()
                workers.append(worker)
                print(f"[local-auto] Capturing {adapter.name}", flush=True)
            if not active:
                raise RuntimeError(
                    "Npcap could not open any adapter. Check Npcap installation/permissions"
                )
            try:
                while not stop.is_set():
                    kind, frame = link.recv()
                    if kind != RESPONSE_MESSAGE or not is_identify_response(frame):
                        continue
                    header = parse_dcp(frame)
                    if header is None:
                        continue
                    source_mac = pending.get(header.xid)
                    if source_mac in active:
                        active[source_mac].send(rewrite_destination(frame, source_mac))
                        if debug:
                            print(
                                f"[local-auto] Response XID={header.xid.hex()} "
                                f"PLC={header.src.hex(':')}",
                                flush=True,
                            )
            finally:
                stop.set()
                for worker in workers:
                    worker.join(timeout=0.5)


def serve_remote_auto(target: str, port: int, *, debug: bool = False) -> None:
    adapters = windows_adapters()
    source_ip = local_ip_for_target(target)
    adapter = select_remote_adapter(
        adapters, source_ip, os.environ.get("RUSTDESK_DCP_REMOTE_GUID", "")
    )
    print(
        f"[remote-auto] PLC target={target}; NIC={adapter.name}, MAC={adapter.mac.hex(':')}",
        flush=True,
    )
    serve_remote(iface_name(adapter.guid), adapter.mac, port,
                 debug=debug, single_connection=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("local-auto", "remote-auto"))
    parser.add_argument("--target", default="", help="PLC-side destination of TCP/102 mapping")
    parser.add_argument("--port", type=int, required=True, help="Loopback DCP forwarding port")
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args(argv)
    if not 1 <= args.port <= 65535:
        parser.error("port must be 1..65535")
    try:
        if args.mode == "local-auto":
            run_local_auto(args.port, debug=args.debug)
        else:
            serve_remote_auto(args.target, args.port, debug=args.debug)
    except KeyboardInterrupt:
        return 0
    except (RuntimeError, OSError, EOFError, ValueError, subprocess.SubprocessError) as exc:
        print(f"PROFINET DCP helper failed: {exc}", file=sys.stderr, flush=True)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
