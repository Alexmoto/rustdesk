#!/usr/bin/env python3
"""Read-only PROFINET DCP Identify transport via an existing RustDesk TCP forward.

Windows only at runtime (Npcap >= 1.83). This deliberately DOES NOT implement
DCP Set, general Layer-2 bridging, PLC IP routing or a substitute for a VPN.
"""
from __future__ import annotations

import argparse
import ctypes
import os
import socket
import struct
import sys
import threading
import time
from dataclasses import dataclass
from typing import Callable

DCP_MULTICAST = bytes.fromhex("01 0e cf 00 00 00")
PROFINET_ETHERTYPE = b"\x88\x92"
FRAME_ID_IDENTIFY_REQUEST = 0xFEFE
FRAME_ID_IDENTIFY_RESPONSE = 0xFEFF
SERVICE_IDENTIFY = 0x05
REQUEST = 0x00
RESPONSE = 0x01
MAX_ETHERNET_FRAME = 1522
MIN_DCP_FRAME = 26
REQUEST_MESSAGE = b"I"
RESPONSE_MESSAGE = b"R"
DEFAULT_PORT = 49092
PENDING_SECONDS = 5.0
BPF_DCP = "ether proto 0x8892 and (ether[14:2] = 0xfefe or ether[14:2] = 0xfeff)"


@dataclass(frozen=True)
class DcpHeader:
    dst: bytes
    src: bytes
    frame_id: int
    service_id: int
    service_type: int
    xid: bytes


def parse_dcp(frame: bytes) -> DcpHeader | None:
    """Parse an untagged Ethernet II PN-DCP frame. Reject truncated frames."""
    if not MIN_DCP_FRAME <= len(frame) <= MAX_ETHERNET_FRAME:
        return None
    if frame[12:14] != PROFINET_ETHERTYPE:
        return None
    dcp_length = int.from_bytes(frame[24:26], "big")
    if len(frame) < 26 + dcp_length:
        return None
    return DcpHeader(
        dst=frame[:6],
        src=frame[6:12],
        frame_id=int.from_bytes(frame[14:16], "big"),
        service_id=frame[16],
        service_type=frame[17],
        xid=frame[18:22],
    )


def is_identify_request(frame: bytes, source_mac: bytes | None = None) -> bool:
    d = parse_dcp(frame)
    return bool(
        d
        and d.dst == DCP_MULTICAST
        and d.frame_id == FRAME_ID_IDENTIFY_REQUEST
        and d.service_id == SERVICE_IDENTIFY
        and d.service_type == REQUEST
        and (source_mac is None or d.src == source_mac)
    )


def is_identify_response(frame: bytes, destination_mac: bytes | None = None) -> bool:
    d = parse_dcp(frame)
    return bool(
        d
        and d.frame_id == FRAME_ID_IDENTIFY_RESPONSE
        and d.service_id == SERVICE_IDENTIFY
        and d.service_type == RESPONSE
        and (destination_mac is None or d.dst == destination_mac)
    )


def rewrite_source(frame: bytes, mac: bytes) -> bytes:
    if len(mac) != 6 or not is_identify_request(frame):
        raise ValueError("Only DCP Identify requests can be forwarded")
    return frame[:6] + mac + frame[12:]


def rewrite_destination(frame: bytes, mac: bytes) -> bytes:
    if len(mac) != 6 or not is_identify_response(frame):
        raise ValueError("Only DCP Identify responses can be returned")
    return mac + frame[6:]


def parse_mac(text: str) -> bytes:
    value = text.replace(":", "").replace("-", "").replace(".", "")
    if len(value) != 12:
        raise argparse.ArgumentTypeError("MAC must have 6 bytes")
    try:
        b = bytes.fromhex(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("MAC must be hexadecimal") from exc
    if b[0] & 1 or b == bytes(6):
        raise argparse.ArgumentTypeError("Use a physical unicast interface MAC")
    return b


def iface_name(guid: str) -> str:
    """Return a Npcap device path from the Windows network adapter GUID."""
    guid = guid.strip().strip("{}").lower()
    import uuid
    try:
        guid = str(uuid.UUID(guid))
    except ValueError as exc:
        raise argparse.ArgumentTypeError("--interface must be a Windows InterfaceGuid") from exc
    return "\\Device\\NPF_{" + guid.upper() + "}"


class PendingXids:
    """Small bounded XID map; stores original TIA MAC for each query."""

    def __init__(self, ttl: float = PENDING_SECONDS, capacity: int = 128):
        self._items: dict[bytes, tuple[bytes, float]] = {}
        self._lock = threading.Lock()
        self._ttl = ttl
        self._capacity = capacity

    def add(self, xid: bytes, mac: bytes) -> None:
        now = time.monotonic()
        with self._lock:
            self._expire(now)
            if len(self._items) >= self._capacity and xid not in self._items:
                oldest = min(self._items, key=lambda x: self._items[x][1])
                self._items.pop(oldest)
            self._items[xid] = (mac, now + self._ttl)

    def get(self, xid: bytes) -> bytes | None:
        with self._lock:
            self._expire(time.monotonic())
            item = self._items.get(xid)
            return None if item is None else item[0]

    def _expire(self, now: float) -> None:
        for xid, (_, deadline) in list(self._items.items()):
            if deadline < now:
                self._items.pop(xid, None)


class FramedSocket:
    """Length-prefixed messages; one writer lock for both capture/receive paths."""

    def __init__(self, sock: socket.socket):
        self.sock = sock
        self.lock = threading.Lock()

    def send(self, kind: bytes, frame: bytes) -> None:
        if kind not in (REQUEST_MESSAGE, RESPONSE_MESSAGE):
            raise ValueError("Invalid message type")
        if not MIN_DCP_FRAME <= len(frame) <= MAX_ETHERNET_FRAME:
            raise ValueError("Invalid Ethernet frame length")
        body = kind + frame
        with self.lock:
            self.sock.sendall(struct.pack("!H", len(body)) + body)

    def recv(self) -> tuple[bytes, bytes]:
        prefix = self._read_exact(2)
        count = int.from_bytes(prefix, "big")
        if not MIN_DCP_FRAME + 1 <= count <= MAX_ETHERNET_FRAME + 1:
            raise ValueError("Invalid tunneled frame length")
        body = self._read_exact(count)
        if body[:1] not in (REQUEST_MESSAGE, RESPONSE_MESSAGE):
            raise ValueError("Invalid message type")
        return body[:1], body[1:]

    def _read_exact(self, size: int) -> bytes:
        chunks = []
        while size:
            b = self.sock.recv(size)
            if not b:
                raise EOFError("RustDesk TCP forwarding connection closed")
            chunks.append(b)
            size -= len(b)
        return b"".join(chunks)


# Npcap's pcap_pkthdr uses struct timeval, which has 32-bit longs on Windows.
class _Timeval(ctypes.Structure):
    _fields_ = [("tv_sec", ctypes.c_long), ("tv_usec", ctypes.c_long)]


class _PcapPkthdr(ctypes.Structure):
    _fields_ = [("ts", _Timeval), ("caplen", ctypes.c_uint), ("len", ctypes.c_uint)]


class _BpfProgram(ctypes.Structure):
    _fields_ = [("bf_len", ctypes.c_uint), ("bf_insns", ctypes.c_void_p)]


class Npcap:
    MODE_SENDTORX = 0x0100  # Npcap >= 1.83; inject as an incoming frame.

    def __init__(self):
        if os.name != "nt":
            raise RuntimeError("Npcap runtime requires Windows")
        dll = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "Npcap", "wpcap.dll")
        if not os.path.isfile(dll):
            raise RuntimeError(f"Npcap wpcap.dll missing: {dll}; install Npcap >= 1.83")
        self.dll = ctypes.WinDLL(dll)
        p = self.dll
        p.pcap_open_live.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_void_p]
        p.pcap_open_live.restype = ctypes.c_void_p
        p.pcap_close.argtypes = [ctypes.c_void_p]
        p.pcap_compile.argtypes = [ctypes.c_void_p, ctypes.POINTER(_BpfProgram), ctypes.c_char_p, ctypes.c_int, ctypes.c_uint]
        p.pcap_compile.restype = ctypes.c_int
        p.pcap_setfilter.argtypes = [ctypes.c_void_p, ctypes.POINTER(_BpfProgram)]
        p.pcap_setfilter.restype = ctypes.c_int
        p.pcap_freecode.argtypes = [ctypes.POINTER(_BpfProgram)]
        p.pcap_next_ex.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.POINTER(_PcapPkthdr)), ctypes.POINTER(ctypes.POINTER(ctypes.c_ubyte))]
        p.pcap_next_ex.restype = ctypes.c_int
        p.pcap_sendpacket.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int]
        p.pcap_sendpacket.restype = ctypes.c_int
        p.pcap_setmode.argtypes = [ctypes.c_void_p, ctypes.c_int]
        p.pcap_setmode.restype = ctypes.c_int
        p.pcap_geterr.argtypes = [ctypes.c_void_p]
        p.pcap_geterr.restype = ctypes.c_char_p

    def open(self, name: str, *, incoming_inject: bool = False) -> "PcapHandle":
        errors = ctypes.create_string_buffer(512)
        h = self.dll.pcap_open_live(name.encode(), 2048, 0, 250, errors)
        if not h:
            raise RuntimeError("Npcap cannot open NIC: " + errors.value.decode(errors="replace"))
        handle = PcapHandle(self, h)
        try:
            if incoming_inject and self.dll.pcap_setmode(h, self.MODE_SENDTORX) != 0:
                raise RuntimeError("Npcap >= 1.83 with MODE_SENDTORX required for local receiver injection")
        except Exception:
            handle.close()
            raise
        return handle


class PcapHandle:
    def __init__(self, api: Npcap, h: int):
        self.api, self.h = api, h

    def close(self) -> None:
        if self.h:
            self.api.dll.pcap_close(self.h)
            self.h = 0

    def __enter__(self) -> "PcapHandle":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def filter_dcp(self) -> None:
        prog = _BpfProgram()
        d = self.api.dll
        if d.pcap_compile(self.h, ctypes.byref(prog), BPF_DCP.encode(), 1, 0xFFFFFFFF) != 0:
            raise RuntimeError("Npcap filter compilation failed")
        try:
            if d.pcap_setfilter(self.h, ctypes.byref(prog)) != 0:
                raise RuntimeError("Npcap filter installation failed")
        finally:
            d.pcap_freecode(ctypes.byref(prog))

    def next_frame(self) -> bytes | None:
        hp = ctypes.POINTER(_PcapPkthdr)()
        packet = ctypes.POINTER(ctypes.c_ubyte)()
        r = self.api.dll.pcap_next_ex(self.h, ctypes.byref(hp), ctypes.byref(packet))
        if r == 0:
            return None
        if r != 1:
            raise RuntimeError("Npcap capture error: " + str(self.api.dll.pcap_geterr(self.h)))
        if hp.contents.caplen > MAX_ETHERNET_FRAME:
            return None
        return ctypes.string_at(packet, hp.contents.caplen)

    def send(self, frame: bytes) -> None:
        buf = ctypes.create_string_buffer(frame)
        if self.api.dll.pcap_sendpacket(self.h, buf, len(frame)) != 0:
            raise RuntimeError("Npcap packet injection failed: " + str(self.api.dll.pcap_geterr(self.h)))


def capture_worker(handle: PcapHandle, stop: threading.Event, process: Callable[[bytes], None]) -> None:
    try:
        while not stop.is_set():
            frame = handle.next_frame()
            if frame is not None:
                process(frame)
    except (OSError, RuntimeError, EOFError, ValueError) as exc:
        print(f"Capture stopped: {exc}", file=sys.stderr)
        stop.set()


def trace_frame(side: str, frame: bytes) -> None:
    header = parse_dcp(frame)
    if header is None:
        print(f"[{side}] DCP frame rejected by parser: length={len(frame)}, "
              f"ethertype={frame[12:14].hex() if len(frame) >= 14 else '?'}", flush=True)
        return
    print(f"[{side}] DCP captured: frame=0x{header.frame_id:04x} "
          f"service=0x{header.service_id:02x} type=0x{header.service_type:02x} "
          f"src={header.src.hex(':')} dst={header.dst.hex(':')} "
          f"xid={header.xid.hex()} bytes={len(frame)}", flush=True)


def run_local(interface: str, local_mac: bytes, port: int, *, debug: bool = False) -> None:
    print(f"Connecting to RustDesk local TCP forward 127.0.0.1:{port}")
    with socket.create_connection(("127.0.0.1", port), timeout=20) as sock:
        print(f"[local] TCP connection established to 127.0.0.1:{port}", flush=True)
        sock.settimeout(None)
        link = FramedSocket(sock)
        api = Npcap()
        pending = PendingXids()
        stop = threading.Event()
        with api.open(interface) as capture, api.open(interface, incoming_inject=True) as inject:
            capture.filter_dcp()
            print(f"[local] Npcap capturing on {interface}; local MAC={local_mac.hex(':')}", flush=True)
            print("[local] Start TIA Portal Accessible devices search on THIS adapter", flush=True)

            def on_request(frame: bytes) -> None:
                if debug:
                    trace_frame("local", frame)
                if not is_identify_request(frame):
                    return
                candidate = parse_dcp(frame)
                if candidate is not None and candidate.src != local_mac:
                    print(f"[local] IGNORED Identify: source MAC {candidate.src.hex(':')} "
                          f"differs from selected NIC {local_mac.hex(':')}. "
                          "Verify TIA PG/PC interface selection.", flush=True)
                    return
                header = parse_dcp(frame)
                assert header is not None
                pending.add(header.xid, header.src)
                link.send(REQUEST_MESSAGE, frame)
                print(f"Identify -> RustDesk XID={header.xid.hex()}")

            worker = threading.Thread(target=capture_worker, args=(capture, stop, on_request), daemon=True)
            worker.start()
            try:
                while not stop.is_set():
                    kind, frame = link.recv()
                    if kind != RESPONSE_MESSAGE or not is_identify_response(frame):
                        continue
                    header = parse_dcp(frame)
                    assert header is not None
                    target = pending.get(header.xid)
                    if target is None:
                        continue
                    inject.send(rewrite_destination(frame, target))
                    print(f"Identify <- RustDesk XID={header.xid.hex()} PLC={header.src.hex(':')}")
            finally:
                stop.set()
                worker.join(timeout=1)


def serve_remote(interface: str, remote_mac: bytes, port: int, *, debug: bool = False) -> None:
    """Listen only on loopback; RustDesk port forwarding terminates here."""
    api = Npcap()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", port))
        listener.listen(1)
        print(f"DCP remote helper listening on 127.0.0.1:{port}")
        while True:
            conn, peer = listener.accept()
            print(f"RustDesk forward connected: {peer}")
            with conn:
                conn.settimeout(None)
                link = FramedSocket(conn)
                pending = PendingXids()
                stop = threading.Event()
                with api.open(interface) as capture, api.open(interface) as inject:
                    capture.filter_dcp()
                    print(f"[remote] Npcap capturing on {interface}; "
                          f"remote MAC={remote_mac.hex(':')}", flush=True)

                    def on_response(frame: bytes) -> None:
                        if debug:
                            trace_frame("remote", frame)
                        if not is_identify_response(frame, remote_mac):
                            return
                        header = parse_dcp(frame)
                        assert header is not None
                        if pending.get(header.xid) is None:
                            return
                        link.send(RESPONSE_MESSAGE, frame)
                        print(f"Identify response PLC={header.src.hex(':')} XID={header.xid.hex()}")

                    worker = threading.Thread(target=capture_worker, args=(capture, stop, on_response), daemon=True)
                    worker.start()
                    try:
                        while not stop.is_set():
                            kind, frame = link.recv()
                            if kind != REQUEST_MESSAGE or not is_identify_request(frame):
                                continue
                            header = parse_dcp(frame)
                            assert header is not None
                            pending.add(header.xid, remote_mac)
                            inject.send(rewrite_source(frame, remote_mac))
                            print(f"Identify multicast -> PLC LAN XID={header.xid.hex()}")
                    except (EOFError, ConnectionError, OSError) as exc:
                        print(f"Forward disconnected: {exc}")
                    finally:
                        stop.set()
                        worker.join(timeout=1)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("local", "remote"))
    parser.add_argument("--debug", action="store_true", help="Print each captured DCP Identify request/response and mismatched MACs")
    parser.add_argument("--interface", required=True, type=iface_name, help="Windows Get-NetAdapter InterfaceGuid")
    parser.add_argument("--mac", required=True, type=parse_mac, help="MAC of selected NIC, from Get-NetAdapter")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="RustDesk forwarded TCP port")
    args = parser.parse_args(argv)
    if not 1 <= args.port <= 65535:
        parser.error("Port must be 1..65535")
    try:
        if args.mode == "remote":
            serve_remote(args.interface, args.mac, args.port, debug=args.debug)
        else:
            run_local(args.interface, args.mac, args.port, debug=args.debug)
    except KeyboardInterrupt:
        print("Stopped")
    except (OSError, RuntimeError, EOFError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())