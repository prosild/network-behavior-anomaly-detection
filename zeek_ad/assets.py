"""연결의 주소 중 점수화 대상 내부 자산을 판정한다."""

import ipaddress
import json
from pathlib import Path


PROJECT_CONFIG = (
    Path(__file__).resolve().parents[1] / "configs" / "assets.cic-ids-2017.v1.json"
)

# 연결 안에서 내부 자산의 위치. 공격자/피해자나 inbound/outbound가 아니다.
ORIGINATOR = "originator"  # 연결을 시작한 쪽 (id.orig_h)
RESPONDER = "responder"  # 연결을 받은 쪽 (id.resp_h)
ROLES = (ORIGINATOR, RESPONDER)


def load_internal_networks(config_path):
    config = json.loads(Path(config_path).read_text(encoding="utf-8"))
    # 기본값 strict=True는 "192.168.10.5/24"처럼 호스트 비트가 있는 값을 거부한다.
    return tuple(ipaddress.ip_network(cidr) for cidr in config["internal_networks"])


def load_networks(config_paths):
    """여러 자산 설정의 내부 대역을 합친다(순서 유지, 중복 제거).

    실습망 그래프(DD-012)는 월요일 CIC 이벤트와 실습망 이벤트를 함께 쓰므로 두 설정의 대역이 모두 필요하다.
    """
    merged = []
    for path in config_paths:
        merged += [n for n in load_internal_networks(path) if n not in merged]
    return tuple(merged)


def is_scored_asset(address, networks):
    # IP가 아닌 값은 조용히 버리지 않고 ValueError를 낸다.
    ip = ipaddress.ip_address(address)
    # IPv6 주소는 IPv4 대역에 포함되지 않으므로 버전 검사를 따로 하지 않는다.
    return any(
        ip in net and ip not in (net.network_address, net.broadcast_address)
        for net in networks
    )


def role_observations(orig_h, resp_h, networks):
    """연결 하나가 만드는 (asset_id, role) 관측을 돌려준다.

    연결 자체를 거르지 않는다. 빈 리스트는 양쪽 모두 점수화 대상이
    아니라는 뜻일 뿐이다.
    """
    observations = []
    if is_scored_asset(orig_h, networks):
        observations.append((orig_h, ORIGINATOR))
    if is_scored_asset(resp_h, networks):
        observations.append((resp_h, RESPONDER))
    return observations
