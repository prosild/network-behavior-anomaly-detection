"""여러 모델의 하루 조사 큐를 순위대로 번갈아 합친다(DD-009, configs/models/fusion.v1.json).

모델마다 점수 척도와 꼬리 모양이 달라 점수를 직접 섞지 않는다. 각 모델 큐의 순위만 쓴다.
표준 라이브러리만 쓴다. 입력은 evaluation.rank_queue로 정렬한 사건 목록이다.

겹친 사건을 다루는 방법은 결합 설정의 overlap_policy로 고른다(fuse).
- skip(v1, 기본): 먼저 뽑힌 사건만 남기고 겹친 사건은 건너뛴다. 창은 늘리지 않는다(fuse_round_robin).
- merge_windows(v2, DD-018): 겹친 사건을 하나로 묶고 범위는 모든 모델 창의 합이다(fuse_merge_overlaps).
등록된 v1 묶음은 설정만 묶음에서 읽고 이 코드는 컨테이너 것을 쓴다. 그래서 v1 동작(fuse_round_robin)은 바꾸지 않는다.
"""

from collections import defaultdict
from dataclasses import replace

from zeek_ad.evaluation import WINDOW_SECONDS

OVERLAP_POLICIES = ("skip", "merge_windows")


def fuse(queues, names, policy="skip"):
    """결합 설정의 overlap_policy에 맞는 함수로 합친다. 반환 형식은 두 함수가 같다."""
    if policy == "skip":
        return fuse_round_robin(queues, names)
    if policy == "merge_windows":
        return fuse_merge_overlaps(queues, names)
    raise ValueError(f"모르는 overlap_policy: {policy} (허용: {OVERLAP_POLICIES})")


def fuse_round_robin(queues, names):
    """queues: 모델 순서대로 정렬된 사건 목록들. names: 같은 순서의 모델 이름.

    1회차에 각 모델의 1위, 2회차에 2위를 가져온다. 이미 뽑힌 사건과 같은 캡처·자산·역할에서
    창을 하나라도 공유하면 건너뛴다(그 모델의 차례는 쓴 것으로 친다).
    반환: (합친 사건 목록, {incident_id: [뽑은 모델, 겹쳐서 건너뛴 모델...]}).
    합친 사건의 score는 -순위다. 순서가 곧 순위이고 동점이 없다.
    """
    fused, sources = [], {}
    taken = defaultdict(dict)  # (capture, asset, role) → {window_start: incident_id}
    for depth in range(max((len(q) for q in queues), default=0)):
        for q, name in zip(queues, names):
            if depth >= len(q):
                continue
            inc = q[depth]
            seen = taken[(inc.capture_id, inc.asset_id, inc.role)]
            hit = next((seen[w] for w in inc.windows if w in seen), None)
            if hit is not None:
                sources[hit].append(name)
                continue
            fused.append(replace(inc, score=-float(len(fused) + 1)))
            sources[inc.incident_id] = [name]
            for w in inc.windows:
                seen[w] = inc.incident_id
    return fused, sources


def fuse_merge_overlaps(queues, names):
    """v2(DD-018): 순위를 번갈아 뽑는 것은 v1과 같다. 겹친 사건은 건너뛰지 않고 먼저 뽑힌 사건에 합친다.

    - 겹침: 같은 캡처·자산·역할에서 창을 하나라도 공유한다(v1과 같다).
    - 새 사건이 이미 뽑힌 사건 여럿과 겹치면 그 사건들도 하나로 합친다. 순위는 그중 가장 먼저 뽑힌 자리다.
      모델별 사건은 이어진 창이라 겹치는 것끼리 합친 범위도 이어진 창이다.
    - 합친 사건의 창 = 묶인 모든 모델 사건 창의 합. 사건 ID·첫 창·끝은 합친 창으로 다시 만든다
      (어느 모델이 먼저 뽑혔든 같은 활동이면 같은 ID). 모델별 30분 상한은 모델 사건에만 적용되고, 합친 사건은 넘을 수 있다.
    - 출처: [처음 뽑은 모델, 겹쳐 꼽은 다른 모델...]. 처음 뽑은 모델은 뒤 목록에 넣지 않는다.
    반환: (합친 사건 목록, {incident_id: [뽑은 모델, 겹쳐 꼽은 모델...]}). score는 v1처럼 -순위다.
    """
    groups = []                     # 뽑힌 순서. 원소: {"first": 처음 뽑은 사건, "models": [...], "windows": set, "alive": bool}
    owner = defaultdict(dict)       # (capture, asset, role) → {window_start: groups 번호}
    for depth in range(max((len(q) for q in queues), default=0)):
        for q, name in zip(queues, names):
            if depth >= len(q):
                continue
            inc = q[depth]
            key = (inc.capture_id, inc.asset_id, inc.role)
            hits = sorted({owner[key][w] for w in inc.windows if w in owner[key]})
            if not hits:
                groups.append({"first": inc, "models": [name], "windows": set(inc.windows), "alive": True})
                target = len(groups) - 1
            else:
                target = hits[0]
                for h in hits[1:]:              # 이 사건이 이어 준 다른 사건들을 가장 앞 순위 사건에 합친다
                    groups[target]["windows"] |= groups[h]["windows"]
                    groups[target]["models"] += groups[h]["models"]
                    groups[h]["alive"] = False
                groups[target]["windows"] |= set(inc.windows)
                groups[target]["models"].append(name)
            for w in groups[target]["windows"]:
                owner[key][w] = target

    fused, sources = [], {}
    for g in groups:
        if not g["alive"]:
            continue
        first, ws = g["first"], tuple(sorted(g["windows"]))
        start = ws[0]
        merged = replace(first, incident_id=f"{first.capture_id}|{first.asset_id}|{first.role}|{start}",
                         first_start=start, last_end=ws[-1] + WINDOW_SECONDS, windows=ws,
                         score=-float(len(fused) + 1))
        picked = g["models"][0]
        fused.append(merged)
        sources[merged.incident_id] = [picked] + [m for m in dict.fromkeys(g["models"][1:]) if m != picked]
    return fused, sources


def picked_score(queue, incident):
    """합친 사건 안에 든, 처음 뽑은 모델 사건들의 점수 최댓값(DB incident.model_score).

    v1은 합친 사건 = 뽑은 모델의 사건 하나라 그 사건 점수 그대로다. v2는 합친 범위 안에 그 모델 사건이 여럿일 수 있다.
    """
    ws = set(incident.windows)
    key = (incident.capture_id, incident.asset_id, incident.role)
    return max(i.score for i in queue if (i.capture_id, i.asset_id, i.role) == key and set(i.windows) <= ws)
