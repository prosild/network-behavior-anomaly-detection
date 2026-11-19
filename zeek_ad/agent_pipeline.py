"""LangGraph 흐름과 같은 일을 하는 일반 함수 버전(DD-002: "먼저 일반 함수로 만들고 LangGraph 버전과 비교한다").

같은 부품(agent_inputs·llm_report·send_decision·slack)을 같은 순서로 부른다. 차이는 다음과 같다.
- 근거 세 갈래를 차례로 부른다(병렬 아님).
- 분석가 검토가 필요하면 analyst_review 표에 대기 행을 남기고 "awaiting_review"로 끝난다. 재개는 resume_review가
  DB 행을 고칠 뿐이다. 이어서 할 단계가 생기면, 그 단계에 필요한 상태(사실 목록·보고서·판단)를 DB에서 다시 읽어야 한다.
  LangGraph는 이 상태를 checkpoint로 들고 있다가 멈춘 노드부터 이어 간다.
"""

import time

from zeek_ad.agent_graph import MAX_EVIDENCE_ROUNDS, REVIEW_CHOICES, REVIEW_SOURCES, context_facts, incident_row
from zeek_ad.agent_inputs import (assemble, collect_baseline, collect_evidence, collect_incident,
                                  facts_from_parts, pseudonym_map)
from zeek_ad.agent_store import save_decision, save_report
from zeek_ad.llm_input import query_sentence, template_report
from zeek_ad.llm_report import call_llm
from zeek_ad.report_guard import guarded_final_report
from zeek_ad.rag import retrieve
from zeek_ad.send_decision import call_decision, policy_decision, shadow_record
from zeek_ad.slack import alerted_before, incident_message, record_delivery


def run_incident(res, job_id, incident_id):
    """사건 하나를 처음부터 끝까지(또는 분석가 대기까지) 처리한다. 반환: 결과와 단계별 지연."""
    conn, ctx, persist = res["conn"], res["ctx"], res.get("persist", True)
    timing = {}

    t = time.time()
    info = collect_incident(conn, job_id, incident_id)
    evidence = collect_evidence(conn, job_id, incident_id)
    baseline = collect_baseline(ctx, info["capture_id"], info["asset"], info["role"], info["first_start"],
                                info["last_end"])
    facts = facts_from_parts(info, evidence, baseline, ctx.nets)
    timing["collect_merge"] = time.time() - t

    t = time.time()
    found, method, _ = retrieve(conn, [query_sentence(facts)], ctx.retrieval, ctx.api_key)
    llm_input, template = assemble(facts, found[0]), template_report(facts, found[0])
    timing["rag"] = time.time() - t

    t = time.time()
    raw = call_llm(res["client_llm"], res["report_config"], res["system_prompt"], llm_input)
    report, kind, verification, call = guarded_final_report(raw, llm_input, template)   # 형식 오류면 템플릿
    if persist:
        save_report(conn, job_id, incident_id, llm_input, report, kind, verification, raw, res["source"],
                    pseudonym_map(evidence, ctx.nets))
    timing["write_report"] = time.time() - t

    t = time.time()
    policy = policy_decision(llm_input["facts"], res["send_config"]["policy"])
    decision = call_decision(res["client_decision"], res["send_config"]["decision_model"], llm_input)
    rounds = 0
    while decision["choice"] == "need_more_evidence" and rounds < MAX_EVIDENCE_ROUNDS:
        state = {"job_id": job_id, "incident_id": incident_id, "llm_input": llm_input}
        llm_input = {**llm_input, "facts": llm_input["facts"] + context_facts(conn, ctx, state)}
        decision = call_decision(res["client_decision"], res["send_config"]["decision_model"], llm_input)
        rounds += 1
    timing["decide"] = time.time() - t

    t = time.time()
    shadow = shadow_record(policy, call["report"], decision)
    if persist:
        save_decision(conn, job_id, incident_id, policy, shadow["llm"], decision, shadow, res["source"])
        if shadow["would_send"] and not alerted_before(conn, job_id, incident_id):   # DD-016 결정 4
            msg = incident_message(incident_row(conn, job_id, incident_id), report, kind,
                                   {"policy": policy, "llm_choice": shadow["llm"], "decision_model": decision},
                                   res["slack_config"])
            record_delivery(conn, job_id, incident_id, report["report_version"], msg, res["slack_config"])
    reasons = [f"{who}={c}" for who, c in REVIEW_SOURCES(shadow)
               if c in REVIEW_CHOICES]
    status = "awaiting_review" if reasons else "done"
    if reasons and persist:
        conn.execute("""INSERT INTO analyst_review (job_id, incident_id, requested_at, reason)
                        VALUES (%s, %s, now(), %s) ON CONFLICT DO NOTHING""", (job_id, incident_id, ", ".join(reasons)))
    timing["deliver"] = time.time() - t
    return {"status": status, "facts": llm_input["facts"], "query": llm_input["query"],
            "candidates": [d["attack_id"] for d in found[0]], "retrieval": method, "report_kind": kind,
            "llm_choice": shadow["llm"], "policy": policy["choice"], "decision_model": decision["choice"],
            "would_send": shadow["would_send"], "evidence_rounds": rounds, "review_reason": ", ".join(reasons),
            "timing": {k: round(v, 2) for k, v in timing.items()}}


def resume_review(conn, job_id, incident_id, action, analyst=None, note=None):
    """분석가 결정 기록. 일반 함수 버전에는 멈춘 실행이 없으므로 DB 행만 고친다."""
    if action not in ("confirm", "dismiss"):
        raise ValueError("action은 confirm 또는 dismiss다")
    conn.execute("""UPDATE analyst_review SET action = %s, analyst = %s, note = %s, decided_at = now()
                    WHERE job_id = %s AND incident_id = %s""", (action, analyst, note, job_id, incident_id))
