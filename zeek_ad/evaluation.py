"""창 점수 → 탐지 사건 → 하루 조사 큐 → 사건 Recall@N (설계 5.2·5.3절).

표준 라이브러리만 쓴다. 입력은 Spark·pandas에서 읽은 dict 목록이다.
- 창 점수: {capture_id, asset_id, role, window_start, score}. 점수는 클수록 이상하다.
- 정답 창: {episode_id, capture_id, asset_id, role, window_start}. 정답 연결이 들어간 창이다.
"""

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import math
import random

TIE_SALT = "zeek-ad-tie-v1"
TIE_KEY_VERSION = 1
WINDOW_SECONDS = 300
MAX_INCIDENT_SECONDS = 1800


def percentile(values, q):
    """선형 보간 분위수(numpy 기본값과 같다). q는 0~100."""
    xs = sorted(values)
    if not xs:
        raise ValueError("empty values")
    pos = (len(xs) - 1) * q / 100
    lo, hi = math.floor(pos), math.ceil(pos)
    return xs[lo] + (xs[hi] - xs[lo]) * (pos - lo)


@dataclass(frozen=True)
class Incident:
    incident_id: str
    capture_id: str
    asset_id: str
    role: str
    first_start: int
    last_end: int
    score: float
    windows: tuple  # 구성 창의 window_start
    tie_key: str


def _utc(seconds):
    return datetime.fromtimestamp(seconds, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def tie_key(capture_sha256, asset_id, role, first_start, last_end):
    # 라벨·점수·UID·실행 ID는 넣지 않는다. 같은 입력이면 언제나 같은 순서가 나온다.
    text = "|".join([TIE_SALT, capture_sha256, asset_id, role, _utc(first_start), _utc(last_end)])
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def build_incidents(window_scores, threshold, capture_sha256):
    """임계값 이상인 창을 자산·역할별로 이어 붙여 사건을 만든다.

    - 연속: 창 시작 차이가 정확히 5분. 사이에 후보가 아닌 창이 있으면 끊는다.
    - 길이 상한: 첫 창 시작부터 30분. 넘으면 다음 사건으로 나눈다.
    - 사건 점수: 구성 창 점수의 최댓값.
    capture_sha256: {capture_id: PCAP sha256}. 캡처가 다르면 병합하지 않는다.
    """
    groups = defaultdict(list)
    for w in window_scores:
        if w["score"] >= threshold:  # 동률도 후보에 넣는다
            groups[(w["capture_id"], w["asset_id"], w["role"])].append(w)

    incidents = []
    for (capture_id, asset_id, role), ws in sorted(groups.items()):
        ws.sort(key=lambda w: w["window_start"])
        current = []
        for w in ws:
            if current and (w["window_start"] - current[-1]["window_start"] != WINDOW_SECONDS
                            or w["window_start"] - current[0]["window_start"] >= MAX_INCIDENT_SECONDS):
                incidents.append(_incident(current, capture_sha256[capture_id]))
                current = []
            current.append(w)
        if current:
            incidents.append(_incident(current, capture_sha256[capture_id]))
    return incidents


def _incident(ws, capture_sha):
    first, last = ws[0]["window_start"], ws[-1]["window_start"] + WINDOW_SECONDS
    c, a, r = ws[0]["capture_id"], ws[0]["asset_id"], ws[0]["role"]
    return Incident(
        incident_id=f"{c}|{a}|{r}|{first}", capture_id=c, asset_id=a, role=r,
        first_start=first, last_end=last, score=max(w["score"] for w in ws),
        windows=tuple(w["window_start"] for w in ws), tie_key=tie_key(capture_sha, a, r, first, last),
    )


def rank_queue(incidents):
    """하루 조사 큐. 점수 내림차순, 동점은 고정 해시 오름차순."""
    return sorted(incidents, key=lambda i: (-i.score, i.tie_key))


def episode_edges(incidents, truth_windows, confirmed_ids):
    """사건 → 대응되는 confirmed 에피소드 집합. 사건 창과 정답 창이 하나라도 겹치면 대응이다."""
    by_key = defaultdict(set)
    for t in truth_windows:
        if t["episode_id"] in confirmed_ids:
            by_key[(t["capture_id"], t["asset_id"], t["role"], t["window_start"])].add(t["episode_id"])
    edges = {}
    for inc in incidents:
        eps = set()
        for start in inc.windows:
            eps |= by_key.get((inc.capture_id, inc.asset_id, inc.role, start), set())
        edges[inc.incident_id] = eps
    return edges


def max_matching(edges):
    """최대 개수 일대일 대응(증가 경로). 사건 ID·에피소드 ID 정렬 순으로 탐색해 재현 가능하다.

    edges: {incident_id: set(episode_id)}. 반환: {episode_id: incident_id}.
    """
    match = {}

    def augment(inc, seen):
        for ep in sorted(edges[inc]):
            if ep in seen:
                continue
            seen.add(ep)
            if ep not in match or augment(match[ep], seen):
                match[ep] = inc
                return True
        return False

    for inc in sorted(edges):
        augment(inc, set())
    return match


def recall_at_n(queue, n, edges, denominator):
    """상위 N의 주 지표(일대일)와 보조 지표(공격 포함). denominator: 그날의 confirmed 에피소드 ID."""
    top = queue[:n]
    top_edges = {i.incident_id: edges[i.incident_id] & denominator for i in top}
    matched = max_matching(top_edges)
    covered = set().union(*top_edges.values()) if top_edges else set()
    d = len(denominator)
    return {
        "n": n, "queue_size": len(top), "denominator": d,
        "matched": len(matched), "recall": len(matched) / d if d else None,
        "covered": len(covered), "inclusive_recall": len(covered) / d if d else None,
        "matching": dict(sorted(matched.items())),
    }


def per_episode_counts(queue, n, edges, denominator):
    """공격별 대응 사건 수, 추가 사건 수, 상위 N 예산 점유율."""
    top = queue[:n]
    out = {}
    for ep in sorted(denominator):
        all_hits = sum(ep in edges[i.incident_id] for i in queue)
        top_hits = sum(ep in edges[i.incident_id] for i in top)
        out[ep] = {"all_incidents": all_hits, "top_incidents": top_hits,
                   "extra_top_incidents": max(top_hits - 1, 0),
                   "budget_share": top_hits / len(top) if top else 0.0}
    return out


def tie_sensitivity(queue, n, edges, denominator, trials=1000, seed=42):
    """N번째 자리에 동점 집합이 걸리면, 남은 자리를 동점 집합에서 균등하게 뽑아 Recall 분포를 본다.

    동점 선택에 대한 근사 기대값이다. 공격 표본의 신뢰구간이 아니다.
    """
    if len(queue) <= n:
        return None
    boundary = queue[n - 1].score
    ties = [i for i in queue if i.score == boundary]
    above = [i for i in queue if i.score > boundary]
    if len(ties) <= n - len(above):
        return None  # 경계에서 잘리는 동점이 없다
    slots = n - len(above)
    rng = random.Random(seed)
    primary, inclusive = [], []
    for _ in range(trials):
        picked = above + rng.sample(ties, slots)
        r = recall_at_n(picked, n, edges, denominator)
        primary.append(r["recall"])
        inclusive.append(r["inclusive_recall"])

    def summary(xs):
        mean = sum(xs) / len(xs)
        sd = math.sqrt(sum((x - mean) ** 2 for x in xs) / (len(xs) - 1)) if len(xs) > 1 else 0.0
        return {"mean": mean, "min": min(xs), "max": max(xs), "mc_se": sd / math.sqrt(len(xs))}

    return {"tie_size": len(ties), "open_slots": slots, "trials": trials, "seed": seed,
            "recall": summary(primary), "inclusive_recall": summary(inclusive)}


def pooled_hits(days, n):
    """하루별 평가 결과(experiment.evaluate)에서 에피소드마다 상위 N 일대일 대응 여부(0/1)를 모은다.

    큐와 상위 N 예산은 하루마다 따로다. 반환: {episode_id: 0 또는 1}. JSON에서 읽은 결과도 받는다.
    알려진 한계(프로젝트 검토 Q57 결함 4): 여러 날에 걸친 에피소드는 마지막 날의 값으로 덮어쓴다. 지금 정답 17건은
    모두 하루짜리라 숫자에는 영향이 없다. 여러 날 에피소드가 생기면 "어느 날이든 맞히면 1"인지 날마다 따로 셀지를
    먼저 정하고 고친다(평가 정의라 결과를 보기 전에 정한다).
    """
    hits = {}
    for r in days.values():
        recall = r["recall"].get(n, r["recall"].get(str(n)))
        matched = set(recall["matching"])
        for ep in r["denominator"]:
            hits[ep] = int(ep in matched)
    return dict(sorted(hits.items()))


def bootstrap_recall_ci(hits, trials=1000, seed=42, level=0.95):
    """에피소드 단위 bootstrap 신뢰구간(백분위수 방식). hits: 에피소드별 0/1 목록.

    에피소드를 같은 개수만큼 복원 추출해 Recall을 다시 센다. 같은 날 공격끼리의 의존성과
    큐 경쟁은 반영하지 않는 근사다. 표본이 16개 수준이라 구간이 넓은 것이 정상이다.
    """
    hits = list(hits)
    k = len(hits)
    rng = random.Random(seed)
    stats = sorted(sum(rng.choice(hits) for _ in range(k)) / k for _ in range(trials))
    alpha = (1 - level) / 2
    return {"recall": sum(hits) / k, "low": percentile(stats, alpha * 100), "high": percentile(stats, (1 - alpha) * 100),
            "episodes": k, "trials": trials, "seed": seed, "level": level}
