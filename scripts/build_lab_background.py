"""실습망 시험의 정상 배경 PCAP을 만든다(DD-017). 배포 VM이 실습용 카드로 재생한다(scripts/lab_replay.sh).

입력 A: CIC 월요일 보류 구간을 잘라낸 PCAP(고전 PCAP 형식). 원본은 읽기만 한다. 자르는 명령(이 PC):
    editcap -F pcap -A 2017-07-03T18:30:00Z -B 2017-07-03T19:05:00Z \\
        CIC-IDS-2017/PCAPs/Monday-WorkingHours.pcap outputs/lab_background/v1/monday-holdout-slice.pcap
B: 11-17 시험과 같은 생성기(tests/pcap_fixture.py lab_traffic). 클라이언트 10.10.0.11·.12, DNS 10.10.0.53(가짜),
   HTTP 서버는 실제 공격 대상인 배포 VM 10.10.0.10. A의 첫 패킷 시각에 맞춰 같은 길이로 만든다.
출력(<out>): background.pcap(A·B를 시각 순서로 합침), manifest.json(그룹별 IP, 주소 대응, 뺀 프레임 수, 해시).

예: python scripts/build_lab_background.py --slice outputs/lab_background/v1/monday-holdout-slice.pcap \\
        --out outputs/lab_background/v1
"""

import argparse
from collections import Counter
from datetime import datetime, timezone
import heapq
import json
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "tests"))
from pcap_fixture import lab_traffic  # noqa: E402
from zeek_ad.lab_background import (MAX_FRAME, address_map, ipv4_hosts, read_pcap, rewrite_frame,  # noqa: E402
                                    write_pcap)
from zeek_ad.provenance import file_record, project_path  # noqa: E402

CIC_INTERNAL = "192.168.10.0/24"      # configs/assets.cic-ids-2017.v1.json
LAB_INTERNAL = "10.10.0.0/24"         # configs/assets.lab.v1.json
A_FIRST_HOST = 100                    # A 예약 대역 10.10.0.100~.199(DD-017)
B_CLIENTS = ("10.10.0.11", "10.10.0.12")
B_DNS = "10.10.0.53"
LAB_TARGET = "10.10.0.10"             # 배포 VM(실제 공격 대상)
KALI = "10.10.0.50"
SOURCE_PCAP = {"path": "CIC-IDS-2017/PCAPs/Monday-WorkingHours.pcap",
               "sha256": "f6eac599358f216b074338813a1cf7be3cc4e91d116e13efc0dc71f2cca11972",
               "sha256_from": "manifests/cic-ids-2017.inputs.v1.json"}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--slice", type=Path, required=True, help="월요일 보류 구간을 자른 고전 PCAP")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--slice-utc", nargs=2, default=["2017-07-03T18:30:00Z", "2017-07-03T19:05:00Z"],
                        metavar=("FROM", "TO"), help="자른 구간(기록용)")
    args = parser.parse_args()
    out = args.out / "background.pcap"
    if out.exists():
        sys.exit(f"이미 있다(덮어쓰지 않는다): {project_path(out)}")

    hosts = ipv4_hosts(read_pcap(args.slice), CIC_INTERNAL)
    mapping = address_map(hosts, CIC_INTERNAL, LAB_INTERNAL, A_FIRST_HOST)
    times = [ts for ts, _ in read_pcap(args.slice)]
    first, last = min(times), max(times)
    seconds = int(last - first) + 1

    dropped = Counter()

    def a_packets():
        for ts, frame in read_pcap(args.slice):
            new, reason = rewrite_frame(frame, mapping)
            if new is None:
                dropped[reason] += 1
                continue
            yield ts, new

    b = sorted(lab_traffic(first, seconds=seconds, clients=B_CLIENTS, server=LAB_TARGET, dns=B_DNS),
               key=lambda p: p[0])
    args.out.mkdir(parents=True, exist_ok=True)
    tmp = out.with_suffix(".pcap.tmp")
    # A는 CIC 원본처럼 시각이 아주 조금 거꾸로 가는 곳이 있다. 순서를 바꾸지 않고(원본 순서 보존) B만 끼워 넣는다
    total = write_pcap(tmp, heapq.merge(a_packets(), b, key=lambda p: p[0]))
    tmp.rename(out)

    lab_hosts = sorted({v for k, v in mapping.items() if v not in ("10.10.0.0", "10.10.0.255")},
                       key=lambda s: int(s.split(".")[-1]))
    manifest = {
        "manifest_id": f"lab-background.{args.out.name}",
        "decision": "docs/design-decisions/DD-017-lab-background-traffic.md",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "note": "재생·합성 배경이다. 결과에 이 그룹을 표시하고 실제 관측 주장과 섞지 않는다.",
        "groups": {
            "A_monday_replay": {"hosts": lab_hosts, "meaning": "CIC 월요일 보류 구간 재생(모델 기준의 정상)"},
            "B_synthetic_normal": {"hosts": list(B_CLIENTS) + [B_DNS],
                                   "meaning": "11-17과 같은 생성기. 10초마다 DNS·HTTP. HTTP 서버는 배포 VM"},
            "lab_target": {"hosts": [LAB_TARGET], "meaning": "배포 VM(실제 호스트, 공격 대상, B의 HTTP 서버)"},
            "attacker": {"hosts": [KALI], "meaning": "Kali(실제 호스트, scripts/lab_scenario.sh)"},
        },
        "a_source": {**SOURCE_PCAP, "slice_utc": args.slice_utc, "slice": file_record(args.slice),
                     "address_map": mapping, "mac": "가짜 로컬 관리 주소(02:00:00:00:01:01·02)",
                     "dropped_frames": dict(dropped), "max_frame_bytes": MAX_FRAME,
                     "replay_mtu": MAX_FRAME - 14},
        "b_source": {"generator": "tests/pcap_fixture.py lab_traffic", "clients": list(B_CLIENTS), "dns": B_DNS,
                     "http_server": LAB_TARGET, "seconds": seconds, "packets": len(b)},
        "duration_seconds": round(last - first, 3),
        "output": {**file_record(out), "packets": total},
    }
    (args.out / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=1) + "\n",
                                            encoding="utf-8")
    print(f"배경 PCAP {project_path(out)}: 패킷 {total:,}(A {total - len(b):,}, B {len(b):,}), "
          f"{manifest['duration_seconds'] / 60:.1f}분, 뺀 프레임 {dict(dropped)}")
    print(f"A 주소 대응 {len(mapping)}개: " + ", ".join(f"{k}→{v}" for k, v in mapping.items()))


if __name__ == "__main__":
    main()
