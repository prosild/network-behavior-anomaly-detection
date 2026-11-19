"""DB의 사건 하나 → LLM 입력(llm-input.v2)과 템플릿 보고서(단계 5b). 배치 스크립트와 LangGraph가 같이 쓴다.

순서(설계 9.1절 Evidence Builder):
1. DB에서 사건 행(큐 순위·꼽은 모델)과 근거 JSON(evidence.v1), 모델별 "후보 창 / 창" 수를 읽는다.
2. Gold v2에서 사건 창과, 같은 자산·역할의 월요일 학습 창을 골라 비교 기준 사실을 만든다.
3. 근거 → 사실 목록(가명·상대 시각·허용 목록, llm_input.build_facts).
4. 사실 목록 → 검색 문장 → ATT&CK 검색(retrieval 설정, 실패 시 BM25).
scripts/build_agent_inputs.py에 있던 함수를 옮겼다. 계산은 같다.
"""

import json
from pathlib import Path

import pandas as pd

from zeek_ad.llm_input import (INPUT_VERSION, LIMITS, MODEL_DESCRIPTIONS, BASELINE_FEATURES, REPRESENTATIVE,
                               Pseudonyms, baseline_facts, build_facts, query_sentence, template_report)
from zeek_ad.provenance import PROJECT_ROOT
from zeek_ad.rag import retrieve

WORKER_INPUTS = PROJECT_ROOT / "configs" / "worker" / "inputs.v1.json"
# 운영 검색 설정. v2는 후보 10개(포트 스캔에서 T1046이 6~10위에 있어 빠졌다, 2026-11-17).
# 평가 동결(configs/agent/freeze.v1.json) 때는 v1(후보 5개)이었다. 동결 결과를 다시 만들려면 v1을 쓴다.
RETRIEVAL = PROJECT_ROOT / "configs" / "rag" / "retrieval.v2.json"
ASSETS = PROJECT_ROOT / "configs" / "assets.cic-ids-2017.v1.json"
# 비교 기준: 모델들이 학습한 것과 같은 월요일 학습 창(split == "train")
BASELINE_CAPTURE, BASELINE_SPLIT = "cic17-mon", "train"
BASELINE_GOLD = PROJECT_ROOT / "outputs" / "gold" / "conn_features_v2"


def read_gold(gold_dir, capture_id):
    cols = ["asset_id", "role", "window_start", "split"] + list(BASELINE_FEATURES)
    g = pd.read_parquet(Path(gold_dir) / "windows", columns=cols + ["capture_id"],
                        filters=[("capture_id", "==", capture_id)])
    return g.astype({"asset_id": str, "role": str})


def rows(frame):
    """창 표 → 사전 목록. 결측(NaN)은 None으로 바꾼다."""
    return [{k: (None if pd.isna(v) else float(v)) for k, v in r.items()}
            for r in frame[list(BASELINE_FEATURES)].to_dict("records")]


def model_windows(conn, job, incident_id):
    """모델별 (사건 창 중 후보 창 수, 사건 창 수). dashboard.incident_model_scores 뷰와 같은 계산을 원래 표로 한다.

    worker 계정은 대시보드 뷰를 읽지 못하므로(최소 권한) 뷰 대신 원래 표를 쓴다. api 계정도 이 표들을 읽을 수 있다.
    """
    return {m: (c, w) for m, c, w in conn.execute(
        """SELECT s.model_name, count(*) FILTER (WHERE s.is_candidate), count(*)
           FROM incident i
           JOIN scoring_job j ON j.job_id = i.job_id AND j.status = 'succeeded'
           JOIN incident_window w ON w.job_id = i.job_id AND w.incident_id = i.incident_id
           JOIN window_score s ON s.job_id = i.job_id AND s.asset_id = i.asset_id AND s.role = i.role
                              AND s.window_start = w.window_start
           WHERE i.job_id = %s AND i.incident_id = %s
           GROUP BY s.model_name""", (job, incident_id)).fetchall()}


class InputContext:
    """여러 사건에 같이 쓰는 것: 내부망 설정, 검색 설정, 캡처별 Gold(처음 쓸 때 읽어 둔다), 월요일 기준 창."""

    def __init__(self, api_key=None, assets=None, worker_inputs=None):
        """assets: 내부 대역 설정 파일 목록(가명의 I·X를 가른다). worker_inputs: 캡처별 Gold 위치를 읽을 입력 묶음 정의.

        기본값은 CIC(configs/assets.cic-ids-2017.v1.json, configs/worker/inputs.v1.json)다.
        실습망 리비전(DD-012)은 configs/assets.lab.v1.json과 <리비전>/worker-inputs.json을 준다.
        """
        self.nets = []
        for path in assets or [ASSETS]:
            self.nets += [n for n in json.loads(Path(path).read_text(encoding="utf-8"))["internal_networks"]
                          if n not in self.nets]
        self.retrieval = json.loads(RETRIEVAL.read_text(encoding="utf-8"))
        worker = json.loads(Path(worker_inputs or WORKER_INPUTS).read_text(encoding="utf-8"))
        self.gold_dirs = {c: PROJECT_ROOT / s["gold_dir"] for s in worker["sets"].values() for c in s["captures"]}
        self.api_key = api_key
        self._gold = {}
        self._base = None

    def gold(self, capture_id):
        if capture_id not in self._gold:
            self._gold[capture_id] = read_gold(self.gold_dirs[capture_id], capture_id)
        return self._gold[capture_id]

    def base(self):
        if self._base is None:
            b = read_gold(BASELINE_GOLD, BASELINE_CAPTURE)
            self._base = b[b.split == BASELINE_SPLIT]
        return self._base


# 근거 수집은 세 갈래로 나뉜다. LangGraph는 이 셋을 병렬 노드로 돌리고(fan-out) facts_from_parts에서 모은다(fan-in).
# 반환값은 checkpoint에 저장되므로 JSON으로 바꿀 수 있는 값(dict·list·숫자·문자열)만 쓴다.

def collect_incident(conn, job_id, incident_id):
    """갈래 1(DB): 사건 행과 모델별 "후보 창 / 창" 수."""
    row = conn.execute("""SELECT j.capture_id, host(i.asset_id), i.role, i.first_start, i.last_end, i.queue_rank,
                                 i.picked_by, i.also_flagged_by
                          FROM incident i JOIN scoring_job j USING (job_id)
                          WHERE i.job_id = %s AND i.incident_id = %s""", (job_id, incident_id)).fetchone()
    if row is None:
        raise LookupError(f"사건이 없다: {job_id} {incident_id}")
    cap, asset, role, t0, t1, rank, picked, also = row
    return {"capture_id": cap, "asset": asset, "role": role, "first_start": int(t0.timestamp()),
            "last_end": int(t1.timestamp()), "queue_rank": rank, "picked_by": picked, "also_flagged_by": list(also),
            "model_windows": {m: [c, w] for m, (c, w) in model_windows(conn, job_id, incident_id).items()}}


def collect_evidence(conn, job_id, incident_id):
    """갈래 2(DB): 근거 요약 JSON(evidence.v1). 실제 IP가 들어 있다. LLM에는 facts_from_parts를 거친 사실만 간다."""
    row = conn.execute("SELECT evidence FROM incident_evidence WHERE job_id = %s AND incident_id = %s",
                       (job_id, incident_id)).fetchone()
    if row is None:
        raise LookupError(f"근거가 없다: {job_id} {incident_id}")
    return row[0]


def collect_baseline(ctx, capture_id, asset, role, first_start, last_end):
    """갈래 3(Gold Parquet): 사건 창 최대값과 같은 자산·역할의 월요일 학습 창 분포 → [[이름, 값], ...]."""
    gold, base = ctx.gold(capture_id), ctx.base()
    inc = gold[(gold.asset_id == asset) & (gold.role == role) & (gold.window_start >= first_start)
               & (gold.window_start < last_end)]
    ref = base[(base.asset_id == asset) & (base.role == role)]
    return [[name, value] for name, value in baseline_facts(rows(inc), rows(ref))]


def facts_from_parts(info, evidence, baseline, nets):
    """세 갈래를 모아 사실 목록을 만든다(가명·상대 시각·허용 목록)."""
    return build_facts(evidence, {"queue_rank": info["queue_rank"], "picked_by": info["picked_by"],
                                  "also_flagged_by": info["also_flagged_by"]},
                       info["model_windows"], nets, baseline=baseline)


def pseudonym_map(evidence, nets):
    """사실 목록 속 가명 → 실제 IP 표. 반환: {"H": ip, "I1": ip, "X1": ip, ...}. DB에만 저장하고 LLM에는 보내지 않는다.

    build_facts가 가명을 매기는 순서(상위 상대 → 대표 연결의 출발·도착)를 그대로 따라 한다.
    llm_input.py는 평가 동결 파일(configs/agent/freeze.v1.json)이라 반환값을 바꾸지 않고 여기서 다시 계산한다.
    순서가 같은지는 tests/test_agent_inputs.py가 build_facts 안의 실제 가명표와 비교해 확인한다.
    """
    pseudo = Pseudonyms(evidence["host"]["ip"], nets)
    for p in evidence["peers"]["top"]:
        pseudo(p["ip"])
    for c in evidence["representative_connections"][:REPRESENTATIVE]:
        pseudo(c["source"]["ip"])
        pseudo(c["destination"]["ip"])
    return {name: ip for ip, name in pseudo.map.items()}


def incident_facts(conn, ctx, job_id, incident_id):
    """DB의 사건 하나 → (사실 목록, 캡처 ID). 세 갈래를 차례로 부른다(일반 함수 버전). 검색은 하지 않는다."""
    info = collect_incident(conn, job_id, incident_id)
    evidence = collect_evidence(conn, job_id, incident_id)
    baseline = collect_baseline(ctx, info["capture_id"], info["asset"], info["role"], info["first_start"],
                                info["last_end"])
    return facts_from_parts(info, evidence, baseline, ctx.nets), info["capture_id"]


def assemble(facts, docs):
    """사실 목록·검색 결과 → LLM 입력(이 JSON만 LLM과 판단 모델에 보낸다)."""
    return {"version": INPUT_VERSION, "model_descriptions": MODEL_DESCRIPTIONS, "notes": LIMITS,
            "facts": facts, "query": query_sentence(facts), "attack_candidates": docs}


def make_llm_input(conn, ctx, job_id, incident_id):
    """사건 하나의 LLM 입력과 템플릿 보고서. 반환: (llm_input, template_report, 검색 방법, 검색 실패 이유)."""
    facts, _ = incident_facts(conn, ctx, job_id, incident_id)
    found, method, error = retrieve(conn, [query_sentence(facts)], ctx.retrieval, ctx.api_key)
    llm_input = assemble(facts, found[0])
    return llm_input, template_report(facts, found[0]), method, error
