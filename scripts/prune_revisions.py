"""실습망 리비전 폴더를 손으로 정리한다(DD-015 "배포 전에 할 일").

다시 계산(scripts/live_recompute.py)이 성공할 때마다 그날 리비전은 자동으로 정리된다. 이 스크립트는 다음에 쓴다.
- 더 이상 파일이 오지 않는 지난 날짜(자동 정리가 다시 돌지 않는다).
- 무엇이 지워질지 미리 보기(--dry-run).
남기는 규칙은 zeek_ad/live_capture.revisions_to_prune에 있다(성공 리비전 최신 keep개 + 그보다 새로운 리비전).
결과(점수·사건·보고서·Slack 기록)는 DB에 그대로 있다. 원본 PCAP과 파일별 Zeek 출력도 건드리지 않는다.

예: python scripts/prune_revisions.py --dry-run
    python scripts/prune_revisions.py --capture lab-20261118
"""

import argparse
import json
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
from zeek_ad.live_capture import prune_revisions  # noqa: E402
from zeek_ad.provenance import project_path  # noqa: E402

CONFIG = PROJECT_ROOT / "configs" / "pipeline" / "live.v1.json"


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--capture", help="캡처 ID(예: lab-20261118). 없으면 모든 캡처")
    parser.add_argument("--keep", type=int, help="남길 성공 리비전 수(기본: 설정의 keep_revisions)")
    parser.add_argument("--dry-run", action="store_true", help="지울 목록만 보여 주고 지우지 않는다")
    parser.add_argument("--config", type=Path, default=CONFIG)
    args = parser.parse_args()
    config = json.loads(args.config.read_text(encoding="utf-8"))
    keep = args.keep if args.keep is not None else config.get("keep_revisions", 2)
    runs = PROJECT_ROOT / config["runs_out"]

    captures = [runs / args.capture] if args.capture else sorted(d for d in runs.iterdir() if d.is_dir())
    total = 0
    for cap in captures:
        if not cap.is_dir():
            sys.exit(f"캡처 폴더가 없다: {project_path(cap)}")
        pruned = prune_revisions(cap, keep, dry_run=args.dry_run)
        total += sum(p["bytes"] for p in pruned)
        print(f"{cap.name}: {'지울' if args.dry_run else '지운'} 리비전 {len(pruned)}개")
        for p in pruned:
            print(f"  {p['revision']}  상태 {p['status']}  작업 {p['job_id']}  {p['bytes'] / 1e6:.0f}MB")
        left = sorted(d.name for d in cap.glob("rev-*") if d.is_dir() and d.name not in {p["revision"] for p in pruned})
        print(f"  남는 리비전: {', '.join(left) or '없음'}")
    print(f"합계 {total / 1e6:.0f}MB{' (dry-run: 지우지 않음)' if args.dry_run else ''}")


if __name__ == "__main__":
    main()
