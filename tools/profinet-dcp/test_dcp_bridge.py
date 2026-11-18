import socket
import time
import unittest
from dcp_bridge import (
    DCP_MULTICAST, FramedSocket, PendingXids, REQUEST_MESSAGE,
    RESPONSE_MESSAGE, iface_name, is_identify_request,
    is_identify_response, parse_dcp, parse_mac, rewrite_destination,
    rewrite_source,
)

LOCAL = bytes.fromhex("02 10 20 30 40 50")
REMOTE = bytes.fromhex("02 10 20 30 40 60")
PLC = bytes.fromhex("28 63 36 2a 11 99")
XID = bytes.fromhex("0d 01 00 24")


def packet(dest, source, fid, service=5, kind=0, xid=XID, payload=b"\xff\xff\x00\x00"):
    frame = dest + source + bytes.fromhex("88 92")
    frame += fid.to_bytes(2, "big") + bytes([service, kind])
    frame += xid + bytes(2) + len(payload).to_bytes(2, "big") + payload
    return frame.ljust(60, b"\x00")


class DcpTests(unittest.TestCase):
    def test_req_resp_rewrite_roundtrip(self):
        req = packet(DCP_MULTICAST, LOCAL, 0xFEFE)
        self.assertTrue(is_identify_request(req, LOCAL))
        self.assertEqual(parse_dcp(req).xid, XID)
        outbound = rewrite_source(req, REMOTE)
        self.assertTrue(is_identify_request(outbound, REMOTE))
        self.assertEqual(outbound[6:12], REMOTE)
        res = packet(REMOTE, PLC, 0xFEFF, kind=1)
        self.assertTrue(is_identify_response(res, REMOTE))
        returned = rewrite_destination(res, LOCAL)
        self.assertEqual(returned[:6], LOCAL)
        self.assertEqual(returned[6:12], PLC)
        self.assertEqual(parse_dcp(returned).xid, XID)
        self.assertEqual(returned[12:], res[12:])

    def test_reject_mutating_packets(self):
        req = packet(DCP_MULTICAST, LOCAL, 0xFEFE)
        for frame in (packet(DCP_MULTICAST, LOCAL, 0xFEFE, service=4),
                      packet(DCP_MULTICAST, LOCAL, 0xFEFE, kind=1),
                      packet(PLC, LOCAL, 0xFEFE),
                      packet(DCP_MULTICAST, LOCAL, 0xFEF4),
                      req[:20],
                      req[:12] + b"\x08\x00" + req[14:]):
            self.assertFalse(is_identify_request(frame))
        with self.assertRaises(ValueError):
            rewrite_source(packet(PLC, LOCAL, 0xFEFE), REMOTE)

    def test_reject_truncated_payload(self):
        bad = bytearray(packet(DCP_MULTICAST, LOCAL, 0xFEFE))
        bad[24:26] = (200).to_bytes(2, "big")
        self.assertIsNone(parse_dcp(bytes(bad)))

    def test_pending_xid(self):
        p = PendingXids(ttl=0.02, capacity=1)
        p.add(XID, LOCAL)
        self.assertEqual(p.get(XID), LOCAL)
        p.add(bytes.fromhex("01 02 03 04"), REMOTE)
        self.assertIsNone(p.get(XID))
        time.sleep(0.03)
        self.assertIsNone(p.get(bytes.fromhex("01 02 03 04")))

    def test_mac_and_interface_validation(self):
        self.assertEqual(parse_mac("02-10-20-30-40-50"), LOCAL)
        self.assertEqual(iface_name("12345678-1234-1234-1234-123456789abc"),
                         r"\Device\NPF_{12345678-1234-1234-1234-123456789ABC}")
        with self.assertRaises(Exception):
            parse_mac("01:0e:cf:00:00:00")

    def test_framing_socket(self):
        left, right = socket.socketpair()
        try:
            t1, t2 = FramedSocket(left), FramedSocket(right)
            request = packet(DCP_MULTICAST, LOCAL, 0xFEFE)
            t1.send(REQUEST_MESSAGE, request)
            self.assertEqual(t2.recv(), (REQUEST_MESSAGE, request))
            response = packet(REMOTE, PLC, 0xFEFF, kind=1)
            t2.send(RESPONSE_MESSAGE, response)
            self.assertEqual(t1.recv(), (RESPONSE_MESSAGE, response))
        finally:
            left.close()
            right.close()


if __name__ == "__main__":
    unittest.main()
