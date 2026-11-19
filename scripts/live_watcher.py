"""파일 단위 자동 파이프라인의 감시 프로그램(DD-012). 기본으로 꺼져 있다.

설정: configs/pipeline/live.v1.json. enabled가 false면 아무것도 하지 않고 끝난다.
한 번 돌 때: 1. 수신 폴더의 새 파일 → 저장 → Zeek. 처리 중에 끊겨(컨테이너 재시작 등) received로 남은 파일도
   이어서 처리한다(stale_received_seconds가 지난 것만). 2. 아직 pipeline_done이 아닌 파일이 있는 날(캡처)마다
scripts/live_recompute.py로 그날 전체를 다시 계산한다(Silver → … → 채점 → 근거). 실패한 리비전은 주기마다 반복하지 않는다.
3. 다시 계산이 성공하면(설정 agent가 true일 때) scripts/live_agent.py로 새 사건을 LangGraph 흐름에 넘긴다(템플릿 알림 먼저).
   에이전트가 일부 사건에서 실패하면(종료 코드가 0이 아님) 새 파일이 오지 않아도 다음 주기에 다시 부른다.
   같은 실패가 되풀이되며 LLM을 계속 부르지 않게 agent_retries번(설정)까지만 한다. 이 기억은 감시 프로그램이 도는 동안만 있다.
- 계속 감시: python scripts/live_watcher.py            (poll_seconds마다 수신 폴더 확인, Ctrl+C로 종료)
- 한 번만:   python scripts/live_watcher.py --once     (cron·systemd timer로 돌릴 때)
- 시험용:    --force 를 붙이면 enabled와 상관없이 실행한다.
- 배포(DD-015): 환경 변수 ZEEKAD_LIVE_ENABLED=1이면 enabled가 false여도 켠다. Compose의 pipeline 서비스가 이렇게 켠다
  (app 프로필로 띄우는 것 자체가 켜겠다는 뜻이다). 이 PC에서 손으로 돌릴 때의 기본값(꺼짐)은 그대로다.
- 재처리:    python scripts/live_watcher.py --retry-failed   (Zeek 단계에서 실패한 파일만 다시. Docker가 멈췄을 때 등)
켜는 방법과 수집 장비 쪽 설정: docs/live-pipeline.md
"""

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
from zeek_ad.db import connect  # noqa: E402
from zeek_ad.ingest import ingest_one, ready_files, recover_stale, retry_failed  # noqa: E402
from zeek_ad.review_resume import decided_reviews  # noqa: E402

CONFIG = PROJECT_ROOT / "configs" / "pipeline" / "live.v1.json"


def pending_captures(conn):
    """Zeek까지 끝났지만 다시 계산이 안 된 파일이 있는 날(캡처). 감시 프로그램이 멈췄다 다시 켜져도 여기서 이어진다."""
    return [r[0] for r in conn.execute("""SELECT DISTINCT capture_id FROM ingest_file
                                          WHERE status = 'zeek_done' ORDER BY capture_id""").fetchall()]


def recompute(capture_id, config_path):
    """그날을 다시 계산한다. 반환: 종료 코드(0 성공, 2 전에 실패한 리비전이라 건너뜀, 그 밖은 실패)."""
    t = time.time()
    result = subprocess.run([sys.executable, str(PROJECT_ROOT / "scripts" / "live_recompute.py"),
                             "--capture", capture_id, "--config", str(config_path), "--skip-failed"],
                            capture_output=True, text=True)
    last = (result.stdout + result.stderr).strip().splitlines()[-1:] or [""]
    print(f"{capture_id}: 다시 계산 종료 코드 {result.returncode}, {time.time() - t:.0f}초 · {last[0][:200]}", flush=True)
    return result.returncode


def run_agent(capture_id, config_path):
    t = time.time()
    result = subprocess.run([sys.executable, str(PROJECT_ROOT / "scripts" / "live_agent.py"),
                             "--capture", capture_id, "--config", str(config_path)], capture_output=True, text=True)
    lines = (result.stdout + result.stderr).strip().splitlines()
    print(f"{capture_id}: 에이전트 종료 코드 {result.returncode}, {time.time() - t:.0f}초", flush=True)
    for line in lines[-12:]:
        print(f"  {line[:300]}", flush=True)
    return result.returncode


def run_resume():
    """분석가 검토 결정으로 멈춘 흐름 재개(DD-019). 결정된 검토가 있을 때만 부른다."""
    t = time.time()
    result = subprocess.run([sys.executable, str(PROJECT_ROOT / "scripts" / "resume_reviews.py")],
                            capture_output=True, text=True)
    lines = (result.stdout + result.stderr).strip().splitlines()
    print(f"검토 재개 종료 코드 {result.returncode}, {time.time() - t:.0f}초", flush=True)
    for line in lines[-8:]:
        print(f"  {line[:300]}", flush=True)
    return result.returncode


def agent_retry_targets(failures, fresh, retries):
    """이번 주기에 에이전트만 다시 부를 캡처. failures: {캡처: 연속 실패 횟수}. 방금 다시 계산한 캡처(fresh)는 뺀다."""
    return [c for c, n in sorted(failures.items()) if c not in fresh and n <= retries]


def note_agent_result(failures, capture_id, code, fresh):
    """에이전트 결과를 기억한다. 성공이면 지운다. 새 다시 계산 뒤의 실패는 1부터 다시 센다(새 자료라 다시 해 볼 만하다)."""
    if code == 0:
        failures.pop(capture_id, None)
    else:
        failures[capture_id] = 1 if fresh else failures.get(capture_id, 0) + 1


def one_pass(config, config_path, agent_failures=None):
    """한 주기. agent_failures: 에이전트가 실패한 캡처와 연속 실패 횟수(주기 사이에 이어지는 dict)."""
    agent_failures = {} if agent_failures is None else agent_failures
    inbox = PROJECT_ROOT / config["inbox"]
    inbox.mkdir(parents=True, exist_ok=True)
    files = ready_files(inbox, config["file_patterns"], config["min_age_seconds"])
    with connect("zeekad_worker") as conn:
        recover_stale(conn, config, config.get("stale_received_seconds", 600))   # 처리 중 끊긴 파일(재시작 등)
        for f in files:
            ingest_one(conn, f, config)
        captures = pending_captures(conn)
        reviews = len(decided_reviews(conn))
    use_agent = config.get("agent", False)
    retry = agent_retry_targets(agent_failures, captures, config.get("agent_retries", 0)) if use_agent else []
    for capture_id in captures:
        if recompute(capture_id, config_path) == 0 and use_agent:
            note_agent_result(agent_failures, capture_id, run_agent(capture_id, config_path), fresh=True)
    for capture_id in retry:
        print(f"{capture_id}: 에이전트 다시 시도({agent_failures[capture_id]}번 실패 뒤)", flush=True)
        note_agent_result(agent_failures, capture_id, run_agent(capture_id, config_path), fresh=False)
    if reviews and use_agent:
        run_resume()
    return len(files), len(captures)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=CONFIG)
    parser.add_argument("--once", action="store_true", help="수신 폴더를 한 번 확인하고 끝낸다")
    parser.add_argument("--force", action="store_true", help="enabled가 false여도 실행한다(시험용)")
    parser.add_argument("--retry-failed", action="store_true", help="Zeek 단계에서 실패한 파일을 다시 처리하고 끝낸다")
    args = parser.parse_args()
    config = json.loads(args.config.read_text(encoding="utf-8"))
    if args.retry_failed:
        with connect("zeekad_worker") as conn:
            ok, bad = retry_failed(conn, config)
        print(f"다시 처리: 성공 {ok}, 실패 {bad}")
        return 0 if bad == 0 else 1
    if not config["enabled"] and not args.force and os.environ.get("ZEEKAD_LIVE_ENABLED") != "1":
        print(f"꺼져 있다(enabled=false): {args.config}. 켜는 방법은 docs/live-pipeline.md")
        return 0
    print(f"감시 시작: {config['inbox']} (패턴 {config['file_patterns']}, {config['poll_seconds']}초마다)", flush=True)
    agent_failures = {}
    while True:
        n, days = one_pass(config, args.config, agent_failures)
        if args.once:
            print(f"받은 파일 {n}개, 다시 계산한 날 {days}개")
            return 0
        time.sleep(config["poll_seconds"])


if __name__ == "__main__":
    raise SystemExit(main())
