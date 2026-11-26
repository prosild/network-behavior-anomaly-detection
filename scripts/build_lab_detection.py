"""실습망 공격 11회의 탐지 여부·걸린 시간 표를 VM DB 내보내기(CSV)에서 만든다(평가 전용).

입력(읽기만): 정답 설정 configs/ground-truth/lab-attacks.v1.json, 내보내기 폴더의
scoring_job·window_score·incident·incident_window·slack_delivery CSV.
출력: <out-dir>/detection.json(전체 결과, 입력 sha256, 정의 요약), <out-dir>/detection.md(표 두 개).
계산 규칙은 zeek_ad/lab_detection.py에 있다. 비율(재현율)은 내지 않는다.

예: python3 scripts/build_lab_detection.py
"""

import argparse
import csv
from datetime import datetime, timezone
import json
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
from zeek_ad.lab_detection import FEW_NORMAL_WINDOWS, THREAD_INFO_SINCE, evaluate, render_markdown  # noqa: E402
from zeek_ad.lab_truth import PROJECT_CONFIG, load_config  # noqa: E402
from zeek_ad.provenance import file_record, project_path  # noqa: E402

TABLES = ["scoring_job", "window_score", "incident", "incident_window", "slack_delivery"]
CODE_FILES = [
    PROJECT_ROOT / "zeek_ad" / "lab_truth.py",
    PROJECT_ROOT / "zeek_ad" / "lab_detection.py",
    PROJECT_ROOT / "zeek_ad" / "windows.py",
    PROJECT_ROOT / "scripts" / "build_lab_detection.py",
]
DEFINITIONS = {
    "last_job": "캡처에서 status = succeeded인 작업 가운데 job_id가 가장 큰 것(J_c). 모델 점수와 조사 큐는 J_c 기준",
    "normal_windows": "J_c의 window_score에서 단위의 split = live 창 가운데, 그 캡처에서 단위가 당사자인 모든 에피소드의 공격 창에 없고 "
                      "실패한 시도(other_activity의 failed_attempt, 그 단위·그 창)의 창도 아닌 것. 연결 확인·정상 배경 창은 든다",
    "normal_window_count": "단위의 평소 창 수는 모델을 합쳐 센다(어느 모델이든 점수가 있는 창). 모델별 normal_windows는 그 모델의 창 수",
    "distinct_model": "공격 창에서 한 번 이상 후보이고, 평소 창이 1개 이상이며, 공격 창 최고 점수 > 평소 최고 점수(같으면 아님). 단위의 평소 창이 0개면 null",
    "attack_alert": "status:*가 아닌 slack_delivery 행 가운데 캡처·자산·역할이 단위와 같고, 그 행의 job_id에서 사건이 가졌던 창이 공격 창과 겹치며, created_at >= t0인 것",
    "latency": "첫 알림 created_at - t0(observed.first_ts_utc). 창이 닫힌 뒤 = 첫 알림 - (알림 시점 사건 창과 공격 창이 겹치는 가장 이른 창의 끝)",
    "channel_visible": "created_at < 2026-11-19T06:20:00Z면 null(스레드 정보 없음). 그 뒤는 thread_parent가 비었거나 reply_broadcast가 참이면 true",
    "absorbed": "J_c에서 공격 창과 겹치는 단위의 사건마다, 그 incident_id의 알림 행(status:* 제외)이 있는데 그 가운데 공격 창 알림이 "
                "하나도 없으면 흡수된 사건. 단위에 다른 공격 창 알림이 있으면 일부 흡수. 흡수된 사건의 알림 시각(first_alert_at)은 t0 앞일 수 있다",
    "absorbed_into_episodes": "흡수된 사건의 알림 행이 같은 단위의 다른 에피소드에서 공격 창 알림이면 그 episode_id",
    "shared_alert": "같은 알림 행(job_id, incident_id, created_at)이 둘 이상의 에피소드에서 단위의 첫 알림이면 shared_with_episodes에 서로를 남긴다",
    "failed_attempt": "other_activity의 kind = failed_attempt 항목의 units·windows_utc 창은 평소 창에서 뺀다(공격 창도 아니다). 뺀 수는 failed_attempt_windows_excluded",
    "table_latency": "표 1의 걸린 시간은 detected일 때만 숫자, indistinct는 괄호 안 참고. JSON에는 판정과 상관없이 값을 남긴다",
    "table_distinct_models": "표 1의 구분된 모델은 detected일 때 판정을 만든 단위의 것(deciding_distinct_models)만. 나머지는 non_deciding_distinct",
    "verdict": "detected: 알림 있고 구분되는 모델이 있는 단위가 있음 > indistinct: 알림 있는 단위는 있으나 구분 안 됨 > "
               "candidate_only: 알림 없이 공격 창 후보만 > missed: 공격 창 후보 없음",
    "scenario_verdict": "실행 가운데 하나라도 detected면 잡힘, 아니면 가장 좋은 판정",
    "timing_note": "모든 알림은 mode = dry_run의 기록 시각이다(실제 Slack 전송 시각이 아니다)",
}


def read_csv(path):
    csv.field_size_limit(sys.maxsize)  # payload 열이 기본 한도보다 길다
    with open(path, encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def minutes(seconds):
    return "—" if seconds is None else f"{seconds / 60:.1f}"


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--export-dir", type=Path,
                        default=PROJECT_ROOT / "outputs" / "lab_eval" / "vm-export-20261126")
    parser.add_argument("--config", type=Path, default=PROJECT_CONFIG)
    parser.add_argument("--out-dir", type=Path, default=PROJECT_ROOT / "outputs" / "lab_eval" / "detection" / "v1")
    args = parser.parse_args()

    config = load_config(args.config)
    paths = {name: args.export_dir / f"{name}.csv" for name in TABLES}
    tables = {name: read_csv(path) for name, path in paths.items()}
    result = evaluate(config, tables)

    output = {
        "detection_version": 1,
        "config": file_record(args.config),
        "config_id": config["config_id"],
        "inputs": [file_record(p) for p in paths.values()],
        "code": [file_record(p) for p in CODE_FILES],
        "definitions": {**DEFINITIONS, "thread_info_since_epoch": THREAD_INFO_SINCE,
                        "few_normal_windows_below": FEW_NORMAL_WINDOWS},
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        **result,
    }
    args.out_dir.mkdir(parents=True, exist_ok=True)
    (args.out_dir / "detection.json").write_text(json.dumps(output, ensure_ascii=False, indent=2) + "\n",
                                                 encoding="utf-8")
    text = render_markdown(result, config, project_path(args.export_dir))
    (args.out_dir / "detection.md").write_text(text, encoding="utf-8")
    for s in result["scenarios"]:
        runs = ", ".join(f"{r['run']}={r['verdict']}({minutes(r['latency_s'])}분)" for r in s["per_run"])
        print(f"{s['scenario']:16s} {s['best_verdict']:14s} {runs}")
    print(f"written={project_path(args.out_dir)}/detection.json, detection.md")


if __name__ == "__main__":
    main()
