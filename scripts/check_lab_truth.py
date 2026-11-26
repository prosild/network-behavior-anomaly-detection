"""실습망 정답 설정(lab-attacks.v1)의 observed가 로컬 conn 로그에 규칙을 적용한 결과와 같은지 확인한다.

- 에피소드마다 연결 수, 첫·끝 ts, 창 목록, 창별 연결 수를 다시 계산해 설정과 비교한다.
- 한 연결(캡처 + 수집 파일 폴더 + uid)이 두 에피소드에 들어가면 실패다.
- 하나라도 다르면 무엇이 다른지 출력하고 종료 코드 1. 파일을 쓰지 않는다.

예: python3 scripts/check_lab_truth.py
"""

import argparse
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
from zeek_ad.lab_truth import (  # noqa: E402
    PROJECT_CONFIG, config_problems, episode_capture, episode_connections, load_config, observe,
    overlapping_connections, read_capture_conn,
)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--config", type=Path, default=PROJECT_CONFIG)
    parser.add_argument("--zeek-root", type=Path, default=PROJECT_ROOT / "outputs" / "live" / "zeek")
    args = parser.parse_args()

    config = load_config(args.config)
    problems = config_problems(config)
    records = {}  # 캡처마다 한 번만 읽는다
    chosen = {}  # 에피소드 → 고른 연결
    for ep in config["episodes"]:
        capture = episode_capture(ep)
        if capture not in records:
            records[capture] = read_capture_conn(args.zeek_root, capture)
            if not records[capture]:
                problems.append(f"{capture}: conn.log가 없다({args.zeek_root / capture})")
        connections = episode_connections(ep, records[capture])
        chosen[ep["episode_id"]] = connections
        got = observe(connections, capture, config["window_seconds"])
        diffs = [k for k in got if got[k] != ep["observed"].get(k)]
        status = "ok" if not diffs else "다름"
        print(f"{ep['episode_id']} {ep['scenario']:16s} conn={got['connections']:5d} "
              f"windows={','.join(got['windows_utc'])} {status}")
        for k in diffs:
            problems.append(f"{ep['episode_id']}.{k}: 설정={ep['observed'].get(k)!r} 계산={got[k]!r}")

    for key, eps in overlapping_connections(chosen).items():
        problems.append(f"연결 {'/'.join(key)}이 에피소드 여럿에 들어감: {eps}")

    if problems:
        print(f"\n실패 {len(problems)}건")
        for p in problems:
            print(f"- {p}")
        sys.exit(1)
    print(f"\n통과: 에피소드 {len(config['episodes'])}개의 observed가 conn 로그와 같고, 겹친 연결이 없다")


if __name__ == "__main__":
    main()
