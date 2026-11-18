import json
import unittest
from auto_bridge import Adapter, parse_adapters, select_remote_adapter

NIC_A = '12345678-1234-1234-1234-123456789abc'
NIC_B = '87654321-4321-4321-4321-cba987654321'


class AutoBridgeTests(unittest.TestCase):
    def test_windows_json_single_adapter(self):
        payload = json.dumps({'Name': 'Ethernet', 'InterfaceGuid': NIC_A,
                              'MacAddress': '02-10-20-30-40-50', 'IPv4': '10.10.10.2'})
        adapters = parse_adapters(payload)
        self.assertEqual(len(adapters), 1)
        self.assertEqual(adapters[0].ipv4, ('10.10.10.2',))

    def test_windows_json_multiple_adapters_skips_multicast(self):
        payload = json.dumps([
            {'Name': 'A', 'InterfaceGuid': NIC_A, 'MacAddress': '02-10-20-30-40-50', 'IPv4': ['10.10.10.2']},
            {'Name': 'B', 'InterfaceGuid': NIC_B, 'MacAddress': '01-0E-CF-00-00-00', 'IPv4': []},
        ])
        adapters = parse_adapters(payload)
        self.assertEqual([a.name for a in adapters], ['A'])

    def test_route_specific_interface_selection(self):
        a = Adapter(NIC_A, bytes.fromhex('02 10 20 30 40 50'), 'A', ('192.168.1.1',))
        b = Adapter(NIC_B, bytes.fromhex('02 10 20 30 40 60'), 'B', ('192.168.2.1',))
        self.assertEqual(select_remote_adapter([a, b], '192.168.2.1'), b)

    def test_remote_ambiguous_fails_safely(self):
        a = Adapter(NIC_A, bytes.fromhex('02 10 20 30 40 50'), 'A')
        b = Adapter(NIC_B, bytes.fromhex('02 10 20 30 40 60'), 'B')
        with self.assertRaises(RuntimeError):
            select_remote_adapter([a, b], None)
        self.assertEqual(select_remote_adapter([a, b], None, NIC_A), a)


if __name__ == '__main__':
    unittest.main()
