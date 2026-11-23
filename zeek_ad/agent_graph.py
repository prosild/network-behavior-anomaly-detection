"""사건 하나를 처리하는 LangGraph 흐름(단계 5b, DD-001·002·011). 입력은 DB의 (job_id, incident_id)다(Q45).

          ┌→ collect_incident ─┐
    START ┼→ collect_evidence ─┼→ merge → rag → early_alert → write_report → decide ─┬─(need_more_evidence, 아직 안 함)→ more_evidence → decide
          └→ collect_baseline ─┘                                      └─→ deliver ─┬─(analyst_review)→ analyst_review → END
                                                                                   └─→ END
    analyst_review(재개) → apply_status → END
- 근거 수집 세 갈래(병렬, fan-out): 사건 행·모델 의견(DB), 근거 요약(DB), 월요일 비교 기준(Gold Parquet).
  merge가 셋을 모두 기다렸다가(fan-in) 사실 목록을 만든다. 근거 요약에는 실제 IP가 있어 checkpoint(langgraph 스키마,
  worker 계정만 읽음)에도 남는다. LLM에는 merge가 만든 사실 목록만 간다.
- rag: 사실 목록에서 만든 검색 문장으로 ATT&CK를 찾는다. 검색 문장이 사실 목록에 기대므로 병렬 갈래가 아니라 merge 뒤에 둔다
  (DD-002 그림은 RAG를 병렬 갈래로 그렸다. 차이는 docs/design-discussion-log.md Q48).
- early_alert: 정책 규칙만으로 전송 여부를 정하고, 보냄이면 템플릿 보고서로 Slack 알림을 먼저 기록한다(Q47).
  LLM 보고서(약 20초)를 기다리지 않게 하려는 것이다. 정책 규칙은 판단 모델이 막지 못하는 필수 조건이라(DD-001) 먼저 보내도 된다.
  deliver가 LLM 보고서로 한 번 더 기록한다(보고서 버전이 달라 다른 메시지). LLM이 실패해 템플릿이면 같은 키라 다시 남지 않는다.
- write_report: LLM 1회 보고서 → 형식 검사(report_guard) → 코드 검증 → 통과면 LLM, 아니면 템플릿(설계 9.1절). DB agent_report에 쓴다.
- 한도 초과(HTTP 429, zeek_ad.quota): rag·write_report·decide의 API 호출은 차단기를 거친다. 한 번 429를 보면 이 그래프(실행 하나)의
  남은 호출은 하지 않는다. 임베딩이 막히면 BM25로 찾고 흐름은 이어진다. LLM 보고서·판단 모델이 막히면 템플릿 보고서만
  남기고(전송 판단 없음) QuotaExhausted로 그 사건을 끝낸다. 판단이 없는 사건은 다음 실행이 다시 고른다
  (agent_store.report_reason의 'retry'). 정책 규칙의 템플릿 알림(early_alert)은 그 전에 이미 나갔다.
- decide: 정책 규칙 + 판단 모델(gemini-decision-1). A단계라 전송은 정책 규칙이 정한다(DD-001 결론, 2026-11-17).
- more_evidence: 판단 모델이 "추가 근거 필요"를 고르면 한 번만 맥락 사실(직전 1시간 같은 자산·역할 창, 같은 날 같은 자산의
  다른 사건)을 더해 다시 판단한다. 반복 상한은 MAX_EVIDENCE_ROUNDS다.
- deliver: 전송 판단을 DB send_decision에 쓰고, 보냄이면 Slack 메시지를 기록한다(dry-run, 중복 방지).
  early_alert·deliver 모두, 이전 작업에서 이미 알린 사건(늘어나 보고서를 다시 만드는 사건)은 기록하지 않는다(DD-016 결정 4).
  판단 모델이 analyst_review면 분석가 대기로 간다(LLM 의견은 기록만 한다, Q49).
- apply_status: 분석가 결정을 사건 상태로 옮긴다(DD-010, DB 함수 dashboard.transition_incident).
  confirm → 열림에서 확인 중으로. dismiss → 확인 중을 거쳐 종료(오탐)로(건너뛰기를 막으므로 두 번 바꾼다).
  이미 그 상태면(대시보드에서 먼저 바꿈) 다시 바꾸지 않는다. 바꾸면 Slack 후속 알림을 기록한다(dry-run).
  재개된 그래프가 checkpoint에 저장된 상태(사건·보고서)를 이어받아 하는 단계다.
- analyst_review: interrupt()로 멈춘다. 상태는 checkpoint(PostgreSQL langgraph 스키마)에 남는다.
  분석가가 confirm(조사 진행) 또는 dismiss(오탐 종료)를 넣어 같은 thread_id로 재개하면 analyst_review 표에 기록하고 끝난다.
  노드는 재개할 때 처음부터 다시 실행되므로, interrupt 앞의 DB 쓰기는 몇 번 실행돼도 결과가 같게(ON CONFLICT) 둔다.
"""

from datetime import datetime, timezone
import operator
import time
from typing import Annotated, TypedDict

from langgraph.errors import GraphInterrupt
from langgraph.graph import END, START, StateGraph
from langgraph.types import interrupt

from zeek_ad.agent_inputs import (assemble, collect_baseline, collect_evidence, collect_incident,
                                  facts_from_parts, pseudonym_map)
from zeek_ad.llm_input import query_sentence, template_report
from zeek_ad.quota import Breaker, GuardedClient, QuotaExhausted, blocked_call, retrieve_once
from zeek_ad.agent_store import save_decision, save_report
from zeek_ad.llm_input import fact_map
from zeek_ad.llm_report import call_llm
from zeek_ad.report_guard import guarded_final_report
from zeek_ad.send_decision import call_decision, policy_decision, shadow_record
from zeek_ad.slack import alerted_before, incident_message, record_delivery, status_message

GRAPH_VERSION = "agent-graph.v1"
MAX_EVIDENCE_ROUNDS = 1
REVIEW_CHOICES = {"analyst_review"}


def REVIEW_SOURCES(shadow):  # noqa: N802 (규칙 상수처럼 쓰는 함수)
    """분석가 대기를 정하는 판단. 판단 모델만 본다(Q49, 2026-11-17).

    LLM 의견은 같은 입력에도 호출마다 달라져서(eval-14·19에서 확인) 대기 목록이 흔들린다. LLM 의견은 기록만 한다.
    판단 모델이 실패하면(choice 없음) 대기하지 않고 정책 규칙대로 끝난다.
    """
    return [("decision_model", shadow["decision_model"])]


class State(TypedDict, total=False):
    job_id: int
    incident_id: str
    info: dict                              # 갈래 1
    evidence: dict                          # 갈래 2
    baseline: list                          # 갈래 3
    facts: list
    llm_input: dict
    template: dict
    retrieval: dict
    report: dict
    report_kind: str
    verification: dict
    llm_call: dict
    policy: dict
    decision: dict
    evidence_rounds: int
    shadow: dict
    delivery: dict
    review_reason: str
    review: dict
    trace: Annotated[list, operator.add]   # 노드마다 한 줄씩 덧붙인다(지연·요약)


# MLflow Tracing(가볍게, 설계 9.2절): 노드 하나 = span 하나. 속성은 노드가 만든 실행 기록(trace 줄)만 옮긴다.
# 그래프 상태 전체(근거 요약의 실제 IP 포함)는 넣지 않는다. 그래서 LangGraph 자동 기록(autolog)은 쓰지 않는다.
SPAN_TYPES = {"collect_incident": "RETRIEVER", "collect_evidence": "RETRIEVER", "collect_baseline": "RETRIEVER",
              "rag": "RETRIEVER", "write_report": "LLM", "decide": "LLM"}


def mark_failed(span, error):
    """span을 오류로 표시하되 예외 종류만 남긴다.

    MLflow는 span 안에서 예외가 나면 예외 문장과 stack trace를 trace에 저장한다. DB 오류 문장에는 사건 ID
    (캡처|실제 IP|역할|시작)가 섞일 수 있어 "민감한 원문을 trace에 넣지 않는다"(설계 9.2절)를 어긴다.
    그래서 span 안에서 예외를 잡아 이 함수로 표시하고, 원래 예외는 span을 닫은 뒤에 다시 던진다.
    """
    span.set_status("ERROR")
    span.set_attribute("zeekad.error_type", type(error).__name__)


def traced(name, fn):
    """노드 함수를 MLflow span으로 감싼다. interrupt는 오류가 아니므로 span을 정상으로 닫고 다시 던진다.
    다른 예외는 span을 오류(예외 종류만)로 닫고 다시 던진다(mark_failed)."""
    import json
    import mlflow

    def run(state):
        paused = failed = None
        with mlflow.start_span(name=name, span_type=SPAN_TYPES.get(name, "CHAIN")) as span:
            span.set_attribute("zeekad.graph_version", GRAPH_VERSION)
            try:
                out = fn(state)
            except GraphInterrupt as e:
                span.set_attribute("zeekad.interrupted", True)
                paused, out = e, None
            except Exception as e:  # noqa: BLE001 (문장은 trace 밖으로, 예외는 그대로 다시 던진다)
                mark_failed(span, e)
                failed, out = e, None
            for t in (out or {}).get("trace", []):
                for k, v in t.items():
                    if k != "node":
                        span.set_attribute(f"zeekad.{k}", v if isinstance(v, (str, int, float, bool))
                                           else json.dumps(v, ensure_ascii=False))
        if paused is not None:
            raise paused
        if failed is not None:
            raise failed
        return out
    return run


def _trace(node, t0, **info):
    return [{"node": node, "seconds": round(time.time() - t0, 2), **info}]


def context_facts(conn, ctx, state):
    """추가 근거: 사건 직전 1시간(12창)의 같은 자산·역할 창과, 같은 날 같은 자산의 다른 사건. 사실 목록 뒤에 붙인다."""
    job, iid = state["job_id"], state["incident_id"]
    capture, asset, role, start = iid.split("|")
    start = int(start)
    gold = ctx.gold(capture)
    prev = gold[(gold.asset_id == asset) & (gold.role == role) & (gold.window_start >= start - 3600)
                & (gold.window_start < start)]
    others = conn.execute("""SELECT queue_rank FROM incident WHERE job_id = %s AND host(asset_id) = %s
                             AND incident_id <> %s ORDER BY queue_rank""", (job, asset, iid)).fetchall()
    n = len(state["llm_input"]["facts"])
    return [
        {"id": f"F{n + 1:02d}", "name": "context.previous_hour_same_host_role",
         "value": {"windows_with_traffic": int(len(prev)),
                   "max_connections_per_window": int(prev.conn_count.max()) if len(prev) else 0}},
        {"id": f"F{n + 2:02d}", "name": "context.other_incidents_same_host_today",
         "value": {"count": len(others), "best_queue_rank": others[0][0] if others else None}},
    ]


def build_graph(res, checkpointer=None):
    """res: {"conn": DB 연결(autocommit), "ctx": InputContext, "client_llm", "client_decision",
             "report_config", "system_prompt", "send_config", "slack_config", "source": 실행 이름,
             "persist": False면 결과 표(agent_report·send_decision·slack_delivery·analyst_review)에 쓰지 않는다(비교 실행용),
             "embed_breaker"·"llm_breaker": 한도 초과 차단기(zeek_ad.quota.Breaker). 없으면 여기서 만든다,
             "tracing": True면 노드마다 MLflow span을 남긴다}."""
    conn, ctx = res["conn"], res["ctx"]
    persist = res.get("persist", True)
    # 차단기는 이 그래프로 처리하는 모든 사건이 같이 쓴다(실행 하나 = 프로세스 하나). 임베딩과 LLM은 한도가 달라 따로 둔다
    embed_breaker = res.get("embed_breaker") or Breaker()
    llm_breaker = res.get("llm_breaker") or Breaker()
    client_llm = GuardedClient(res["client_llm"], llm_breaker)
    client_decision = GuardedClient(res["client_decision"], llm_breaker)

    def collect_incident_node(state):
        t0 = time.time()
        info = collect_incident(conn, state["job_id"], state["incident_id"])
        return {"info": info, "trace": _trace("collect_incident", t0, queue_rank=info["queue_rank"],
                                               models=sorted(info["model_windows"]))}

    def collect_evidence_node(state):
        t0 = time.time()
        evidence = collect_evidence(conn, state["job_id"], state["incident_id"])
        return {"evidence": evidence, "trace": _trace("collect_evidence", t0,
                                                       connections=evidence["connection_count"])}

    def collect_baseline_node(state):
        t0 = time.time()
        capture, asset, role, _ = state["incident_id"].split("|")
        span = conn.execute("SELECT first_start, last_end FROM incident WHERE job_id = %s AND incident_id = %s",
                            (state["job_id"], state["incident_id"])).fetchone()
        baseline = collect_baseline(ctx, capture, asset, role, int(span[0].timestamp()), int(span[1].timestamp()))
        return {"baseline": baseline, "trace": _trace("collect_baseline", t0, facts=len(baseline),
                                                       baseline_windows=baseline[0][1]["baseline_windows"])}

    def merge(state):
        t0 = time.time()
        facts = facts_from_parts(state["info"], state["evidence"], state["baseline"], ctx.nets)
        return {"facts": facts, "evidence_rounds": 0, "trace": _trace("merge", t0, facts=len(facts))}

    def rag(state):
        t0 = time.time()
        query = query_sentence(state["facts"])
        found, method, error = retrieve_once(conn, query, ctx.retrieval, ctx.api_key, embed_breaker)
        llm_input = assemble(state["facts"], found[0])
        return {"llm_input": llm_input, "template": template_report(state["facts"], found[0]),
                "retrieval": {"method": method, "fallback_reason": error},
                "trace": _trace("rag", t0, method=method, query=query,
                                candidates=[d["attack_id"] for d in found[0]])}

    def early_alert(state):
        t0 = time.time()
        policy = policy_decision(state["facts"], res["send_config"]["policy"])
        recorded, skipped = False, None
        if policy["choice"] == "send" and persist and alerted_before(conn, state["job_id"], state["incident_id"]):
            skipped = "alerted_before"            # 이전 작업에서 이미 알린 사건(늘어나 다시 처리하는 중). DD-016 결정 4
        elif policy["choice"] == "send" and persist:
            inc = incident_row(conn, state["job_id"], state["incident_id"])
            msg = incident_message(inc, state["template"], "template",
                                   {"policy": policy, "llm_choice": None, "decision_model": None}, res["slack_config"])
            recorded = record_delivery(conn, state["job_id"], state["incident_id"],
                                       state["template"]["report_version"], msg, res["slack_config"])
        return {"trace": _trace("early_alert", t0, policy=policy["choice"], slack_recorded=recorded,
                                slack_skipped=skipped)}

    def write_report(state):
        t0 = time.time()
        if llm_breaker.open:       # 앞 사건에서 한도 초과를 봤다. 부르지 않는다
            raw = blocked_call(res["report_config"].get("model"))
        else:
            raw = call_llm(client_llm, res["report_config"], res["system_prompt"], state["llm_input"])
        # 형식이 틀린 응답은 템플릿으로(report_guard). DB에는 LLM 원래 출력(raw)을, 상태에는 검사한 기록(call)을 둔다
        report, kind, verification, call = guarded_final_report(raw, state["llm_input"], state["template"])
        blocked = llm_breaker.open   # 이 호출이 429였거나 부르지 않았다
        if persist:
            # 한도 초과 때의 템플릿은 이 사건에 보고서가 없을 때만 남긴다(앞 시도가 쓴 LLM 보고서를 덮지 않는다)
            save_report(conn, state["job_id"], state["incident_id"], state["llm_input"], report, kind, verification,
                        raw, res["source"], pseudonym_map(state["evidence"], ctx.nets), overwrite=not blocked)
        if blocked:
            raise QuotaExhausted("LLM 보고서: 한도 초과(429). 전송 판단 없이 끝내고 다음 실행에서 다시 한다")
        return {"report": report, "report_kind": kind, "verification": verification, "llm_call": call,
                "trace": _trace("write_report", t0, report_kind=kind, model_version=call["model_version"],
                                usage=call.get("usage"), attempts=call.get("attempts"), error=call.get("error"),
                                problems=len(verification["problems"]),
                                llm_send=(call["report"] or {}).get("send_recommendation", {}).get("choice"))}

    def decide(state):
        t0 = time.time()
        policy = policy_decision(state["llm_input"]["facts"], res["send_config"]["policy"])
        decision = call_decision(client_decision, res["send_config"]["decision_model"], state["llm_input"])
        if llm_breaker.open:
            raise QuotaExhausted("판단 모델: 한도 초과(429). 전송 판단 없이 끝내고 다음 실행에서 다시 한다")
        return {"policy": policy, "decision": decision,
                "trace": _trace("decide", t0, policy=policy["choice"], mandatory=policy["mandatory"],
                                decision_model=decision["choice"], probabilities=decision["probabilities"])}

    def more_evidence(state):
        t0 = time.time()
        extra = context_facts(conn, ctx, state)
        llm_input = {**state["llm_input"], "facts": state["llm_input"]["facts"] + extra}
        return {"llm_input": llm_input, "evidence_rounds": state["evidence_rounds"] + 1,
                "trace": _trace("more_evidence", t0, added=[f"{f['id']} {f['name']} {f['value']}" for f in extra])}

    def deliver(state):
        t0 = time.time()
        llm_report = state["llm_call"]["report"]
        shadow = shadow_record(state["policy"], llm_report, state["decision"])
        if persist:
            save_decision(conn, state["job_id"], state["incident_id"], state["policy"], shadow["llm"],
                          state["decision"], shadow, res["source"])
        delivery = {"would_send": shadow["would_send"], "recorded": False, "skipped": None}
        if shadow["would_send"] and persist and alerted_before(conn, state["job_id"], state["incident_id"]):
            delivery["skipped"] = "alerted_before"   # DD-016 결정 4: 다시 보내지 않는다. 대시보드가 새 보고서를 보여 준다
        elif shadow["would_send"] and persist:
            inc = incident_row(conn, state["job_id"], state["incident_id"])
            msg = incident_message(inc, state["report"], state["report_kind"],
                                   {"policy": state["policy"], "llm_choice": shadow["llm"],
                                    "decision_model": state["decision"]}, res["slack_config"],
                                   note="LLM 보고서 추가(먼저 보낸 알림은 템플릿)" if state["report_kind"] == "llm" else None)
            delivery["recorded"] = record_delivery(conn, state["job_id"], state["incident_id"],
                                                   state["report"]["report_version"], msg, res["slack_config"])
        reasons = [f"{who}={c}" for who, c in REVIEW_SOURCES(shadow)
                   if c in REVIEW_CHOICES]
        return {"shadow": shadow, "delivery": delivery, "review_reason": ", ".join(reasons),
                "trace": _trace("deliver", t0, would_send=shadow["would_send"], slack_recorded=delivery["recorded"],
                                slack_skipped=delivery["skipped"], review=bool(reasons))}

    def analyst_review(state):
        # 재개하면 이 노드가 처음부터 다시 돈다. 아래 INSERT는 두 번 돌아도 한 행이다.
        if persist:
            conn.execute("""INSERT INTO analyst_review (job_id, incident_id, requested_at, reason)
                            VALUES (%s, %s, now(), %s) ON CONFLICT DO NOTHING""",
                         (state["job_id"], state["incident_id"], state["review_reason"]))
        f = fact_map(state["llm_input"]["facts"])
        answer = interrupt({"job_id": state["job_id"], "incident_id": state["incident_id"],
                            "reason": state["review_reason"], "queue_rank": f["queue_rank"]["value"],
                            "summary": state["report"]["observation_summary"],
                            "ask": "action=confirm(조사 진행) 또는 dismiss(오탐 종료), analyst, note"})
        t0 = time.time()
        if answer.get("action") not in ("confirm", "dismiss"):
            raise ValueError("action은 confirm 또는 dismiss다")
        if persist:
            # 대시보드가 decide_review로 먼저 넣은 결정이면 같은 값이다. 결정 시각은 처음 것을 둔다(DD-019)
            conn.execute("""UPDATE analyst_review SET action = %s, analyst = %s, note = %s,
                                   decided_at = coalesce(decided_at, now())
                            WHERE job_id = %s AND incident_id = %s""",
                         (answer["action"], answer.get("analyst"), answer.get("note"), state["job_id"],
                          state["incident_id"]))
        return {"review": {**answer, "decided_at": datetime.now(timezone.utc).isoformat()},
                "trace": _trace("analyst_review", t0, action=answer["action"])}

    def apply_status(state):
        t0 = time.time()
        review = state["review"]
        actor = review.get("analyst") or "analyst"
        reason = review.get("note") or f"분석가 {review['action']}"
        steps = [("investigating", None)]
        if review["action"] == "dismiss":
            steps.append(("closed", "false_positive"))
        done = []
        if persist:
            for to, resolution in steps:
                # 상태는 사건 ID에 붙는다(migration 012). 다른 작업에서 이미 바꿨어도 여기서 보인다.
                now = conn.execute("""SELECT coalesce((SELECT status FROM incident_status
                                       WHERE incident_id = %s), 'open')""",
                                   (state["incident_id"],)).fetchone()[0]
                order = ["open", "investigating", "closed"]
                if order.index(now) >= order.index(to):
                    continue                      # 이미 그 상태이거나 더 나아감(대시보드에서 먼저 바꿈)
                conn.execute("SELECT dashboard.transition_incident(%s, %s, %s, %s, %s, %s)",
                             (state["job_id"], state["incident_id"], to, actor, reason, resolution))
                inc = incident_row(conn, state["job_id"], state["incident_id"])
                record_delivery(conn, state["job_id"], state["incident_id"], f"status:{to}",
                                status_message(inc, to, resolution, actor, reason, res["slack_config"]),
                                res["slack_config"])
                done.append(to)
        return {"trace": _trace("apply_status", t0, action=review["action"], transitions=done)}

    def after_decide(state):
        if state["decision"]["choice"] == "need_more_evidence" and state["evidence_rounds"] < MAX_EVIDENCE_ROUNDS:
            return "more_evidence"
        return "deliver"

    def after_deliver(state):
        return "analyst_review" if state["review_reason"] else END

    g = StateGraph(State)
    for name, fn in [("collect_incident", collect_incident_node), ("collect_evidence", collect_evidence_node),
                     ("collect_baseline", collect_baseline_node), ("merge", merge), ("rag", rag),
                     ("early_alert", early_alert),
                     ("write_report", write_report), ("decide", decide), ("more_evidence", more_evidence),
                     ("deliver", deliver), ("analyst_review", analyst_review),
                     ("apply_status", apply_status)]:
        g.add_node(name, traced(name, fn) if res.get("tracing") else fn)
    for branch in ("collect_incident", "collect_evidence", "collect_baseline"):
        g.add_edge(START, branch)                      # fan-out: 같은 단계에서 함께 실행
    g.add_edge(["collect_incident", "collect_evidence", "collect_baseline"], "merge")   # fan-in: 셋 다 끝나야 시작
    g.add_edge("merge", "rag")
    g.add_edge("rag", "early_alert")
    g.add_edge("early_alert", "write_report")
    g.add_edge("write_report", "decide")
    g.add_conditional_edges("decide", after_decide, ["more_evidence", "deliver"])
    g.add_edge("more_evidence", "decide")
    g.add_conditional_edges("deliver", after_deliver, ["analyst_review", END])
    g.add_edge("analyst_review", "apply_status")
    g.add_edge("apply_status", END)
    return g.compile(checkpointer=checkpointer)


def incident_row(conn, job_id, incident_id):
    r = conn.execute("""SELECT j.capture_id, i.queue_rank, host(i.asset_id), i.role, i.first_start, i.last_end,
                               i.picked_by, i.also_flagged_by
                        FROM incident i JOIN scoring_job j USING (job_id)
                        WHERE i.job_id = %s AND i.incident_id = %s""", (job_id, incident_id)).fetchone()
    cap, rank, asset, role, t0, t1, picked, also = r
    return {"job_id": job_id, "incident_id": incident_id, "capture_id": cap, "queue_rank": rank, "asset": asset,
            "role": role, "first_start": t0, "last_end": t1, "picked_by": picked, "also_flagged_by": also}
