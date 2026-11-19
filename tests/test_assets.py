import unittest

from zeek_ad.assets import (
    PROJECT_CONFIG, is_scored_asset, load_internal_networks, load_networks, role_observations,
)


NETWORKS = load_internal_networks(PROJECT_CONFIG)


class ScoredAssetTest(unittest.TestCase):
    def test_host_addresses_are_scored(self):
        # .1·.3은 호스트로 유지한다. 장비·서비스 정체는 별도 근거로 확인한다.
        for address in ["192.168.10.1", "192.168.10.3", "192.168.10.50", "192.168.10.254"]:
            self.assertTrue(is_scored_asset(address, NETWORKS), address)

    def test_network_and_broadcast_are_not_scored(self):
        for address in ["192.168.10.0", "192.168.10.255"]:
            self.assertFalse(is_scored_asset(address, NETWORKS), address)

    def test_outside_addresses_are_not_scored(self):
        # NAT 주소, 멀티캐스트, 이름이 비슷한 다른 대역, IPv6 링크 로컬.
        for address in ["172.16.0.1", "224.0.0.251", "192.168.100.5", "fe80::1"]:
            self.assertFalse(is_scored_asset(address, NETWORKS), address)

    def test_invalid_address_raises(self):
        with self.assertRaises(ValueError):
            is_scored_asset("-", NETWORKS)


class RoleObservationTest(unittest.TestCase):
    def test_internal_to_internal_gives_both_roles(self):
        self.assertEqual(
            role_observations("192.168.10.8", "192.168.10.3", NETWORKS),
            [("192.168.10.8", "originator"), ("192.168.10.3", "responder")],
        )

    def test_host_to_broadcast_keeps_originator_only(self):
        self.assertEqual(
            role_observations("192.168.10.5", "192.168.10.255", NETWORKS),
            [("192.168.10.5", "originator")],
        )

    def test_nat_to_internal_gives_responder_only(self):
        self.assertEqual(
            role_observations("172.16.0.1", "192.168.10.50", NETWORKS),
            [("192.168.10.50", "responder")],
        )

    def test_no_scored_endpoint_gives_no_observation(self):
        self.assertEqual(role_observations("fe80::1", "ff02::1", NETWORKS), [])


class MergedNetworksTest(unittest.TestCase):
    def test_lab_and_cic_networks_are_merged_once(self):
        lab = PROJECT_CONFIG.parent / "assets.lab.v1.json"
        merged = load_networks([PROJECT_CONFIG, lab, PROJECT_CONFIG])
        self.assertEqual([str(n) for n in merged], ["192.168.10.0/24", "10.10.0.0/24"])
        self.assertTrue(is_scored_asset("10.10.0.11", merged))
        self.assertTrue(is_scored_asset("192.168.10.5", merged))


if __name__ == "__main__":
    unittest.main()
