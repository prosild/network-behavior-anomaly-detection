"""합성 APT 주입 평가(DD-008). 창 점수 → 사건 → 하루 조사 큐 → 합성 에피소드 Recall@N.

- 주 지표: 조사 큐에서 CIC confirmed 에피소드와 겹치는 사건을 뺀 큐(이미 처리된 공격으로 본다).
- 보조 지표: CIC 사건을 빼지 않은 전체 큐.
사건 만들기·순위·대응 규칙은 CIC 평가(evaluation.py)와 같다. 표준 라이브러리만 쓴다.
"""

from collections import defaultdict

from zeek_ad.evaluation import (
    bootstrap_recall_ci, build_incidents, episode_edges, rank_queue, recall_at_n, tie_sensitivity,
)

NS = [5, 10, 20, 50]


def as_capture(truth_windows, capture_id):
    """원래 날의 정답 창을 합성 캡처 ID로 옮긴다. 합성 캡처는 원래 날의 사본이라 창 키가 같다."""
    return [{**t, "capture_id": capture_id} for t in truth_windows]


def day_queues(window_scores, threshold, capture_sha, cic_truth, cic_confirmed):
    """하루의 전체 큐와 CIC 사건을 뺀 큐를 돌려준다.

    cic_truth: 이 합성 캡처 ID로 옮긴 CIC 정답 창. 사건 창 하나라도 CIC confirmed 정답 창과 겹치면 뺀다.
    """
    queue = rank_queue(build_incidents(window_scores, threshold, capture_sha))
    cic_edges = episode_edges(queue, cic_truth, cic_confirmed)
    main = [i for i in queue if not cic_edges[i.incident_id]]
    return queue, main, cic_edges


def queue_result(queue, edges, denominator):
    """큐 하나의 N별 Recall, 에피소드별 최고 순위, @10 동점 민감도."""
    best = {}
    for k, inc in enumerate(queue, 1):
        for ep in edges[inc.incident_id] & denominator:
            best.setdefault(ep, k)
    return {"incidents": len(queue),
            "recall": {n: recall_at_n(queue, n, edges, denominator) for n in NS},
            "best_rank": {ep: best.get(ep) for ep in sorted(denominator)},
            "tie_sensitivity_at_10": tie_sensitivity(queue, 10, edges, denominator)}


def evaluate_day(window_scores, threshold, capture_sha, syn_truth, syn_ids, cic_truth, cic_confirmed):
    """합성 캡처 하루를 평가한다. window_scores는 capture_edge 창을 뺀 그날의 창 점수다."""
    queue, main, cic_edges = day_queues(window_scores, threshold, capture_sha, cic_truth, cic_confirmed)
    edges = episode_edges(queue, syn_truth, syn_ids)
    denominator = {t["episode_id"] for t in syn_truth} & syn_ids
    by_key = defaultdict(list)
    for w in window_scores:
        by_key[(w["asset_id"], w["role"], w["window_start"])].append(w["score"])
    diagnosis = {}
    for ep in sorted(denominator):
        scores = [s for t in syn_truth if t["episode_id"] == ep
                  for s in by_key.get((t["asset_id"], t["role"], t["window_start"]), [])]
        # numpy 값은 JSON에 문자열("False")로 남으므로 파이썬 float·bool로 바꾼다.
        diagnosis[ep] = {"max_window_score": float(max(scores)) if scores else None,
                         "candidate": bool(scores) and bool(max(scores) >= threshold)}
    return {
        "denominator": sorted(denominator),
        "candidate_windows": int(sum(w["score"] >= threshold for w in window_scores)),
        "excluded_cic_incidents": len(queue) - len(main),
        # 합성 사건이 CIC 사건으로 빠지면 주 지표가 낮게 나온다. 주입 위치 규칙상 0이어야 한다.
        "excluded_with_synthetic": sum(bool(cic_edges[i.incident_id]) and bool(edges[i.incident_id]) for i in queue),
        "diagnosis": diagnosis,
        "main": queue_result(main, edges, denominator),
        "all": queue_result(queue, edges, denominator),
    }


def pooled(days, queue, n):
    """에피소드마다 상위 N 일대일 대응 여부(0/1). 큐와 예산은 하루마다 따로다."""
    hits = {}
    for r in days.values():
        matched = set(r[queue]["recall"][n]["matching"])
        for ep in r["denominator"]:
            hits[ep] = int(ep in matched)
    return dict(sorted(hits.items()))


def summarize(days, pattern_of):
    """네 날을 합친 Recall@N(bootstrap 구간 포함)과 패턴별 @10 결과."""
    out = {}
    for queue in ["main", "all"]:
        out[queue] = {}
        for n in NS:
            hits = pooled(days, queue, n)
            out[queue][n] = {"matched": sum(hits.values()), "episodes": len(hits),
                             "ci": bootstrap_recall_ci(hits.values())}
    patterns = defaultdict(dict)
    hits10 = pooled(days, "main", 10)
    for cap, r in days.items():
        for ep in r["denominator"]:
            patterns[pattern_of[ep]][cap] = {"hit_at_10": hits10[ep], "best_rank": r["main"]["best_rank"][ep],
                                             "candidate": r["diagnosis"][ep]["candidate"]}
    out["patterns"] = dict(sorted(patterns.items()))
    return out
