"""Slack 전송 판단 세 가지(정책 규칙·일반 LLM·판단 모델)를 같은 사건에 만든다(단계 5b-3, DD-001 A단계·DD-011).

- 정책 규칙: 필수 전송 조건(결합 큐 N위 이내 또는 k개 이상 모델이 꼽음)이면 send, 아니면 hold. A단계에서 실제 전송을 정한다.
- 일반 LLM: 5b-2 보고서의 send_recommendation을 그대로 쓴다(추가 호출 없음).
- 판단 모델(gemini-decision-1): 같은 LLM 입력(llm-input.v2)으로 선택지별 확률을 받는다. 기록만 하고 전송에는 쓰지 않는다.
confidence는 가장 큰 확률값일 뿐 정확도가 아니다(DD-001).
"""

import json
import time

from zeek_ad.llm_input import fact_map


def policy_decision(facts, policy):
    """정책 규칙 판단. 반환: {"choice", "mandatory", "reasons"}. 사실 목록에서 큐 순위와 꼽은 모델 수를 읽는다."""
    f = fact_map(facts)
    rule = policy["mandatory_send"]
    rank = f["queue_rank"]["value"]
    models = 1 + len(f["also_flagged_by_models"]["value"])
    reasons = []
    if rank <= rule["max_queue_rank"]:
        reasons.append(f"queue_rank {rank} <= {rule['max_queue_rank']}")
    if models >= rule["min_flagging_models"]:
        reasons.append(f"flagging_models {models} >= {rule['min_flagging_models']}")
    mandatory = bool(reasons)
    return {"policy_id": policy["policy_id"], "choice": "send" if mandatory else policy["otherwise"],
            "mandatory": mandatory, "reasons": reasons}


def decision_request(llm_input, config):
    """판단 모델에 보내는 요청 본문(input 문자열과 questions)."""
    return {"input": json.dumps(llm_input, ensure_ascii=False),
            "questions": {config["question_id"]: {"type": "choice", "criteria": config["criteria"],
                                                  "instructions": config["instructions"]}}}


def call_decision(client, config, llm_input):
    """판단 모델 호출(일시 오류만 config["retries"]번 다시). 반환: 호출 기록."""
    req = decision_request(llm_input, config)
    record = {"model": config["model"], "seconds": None, "attempts": 0, "error": None,
              "choice": None, "probabilities": None, "confidence": None}
    t0 = time.time()
    for attempt in range(config["retries"] + 1):
        record["attempts"] = attempt + 1
        try:
            resp = client.decisions.create(model=config["model"], input=req["input"], questions=req["questions"])
            a = resp.answers[config["question_id"]]
            if a.choice not in config["criteria"]:
                raise ValueError("criteria 밖의 선택")
            record.update(choice=a.choice, confidence=a.confidence, error=None,
                          probabilities={k: round(v, 4) for k, v in dict(a.probabilities).items()})
            break
        except ValueError as e:
            record["error"] = f"format: {type(e).__name__}"
            break
        except Exception as e:  # 오류 문장에 입력이 섞일 수 있어 종류만 남긴다
            record["error"] = f"call: {type(e).__name__}"
            if attempt < config["retries"]:
                time.sleep(3)
    record["seconds"] = round(time.time() - t0, 2)
    return record


def shadow_record(policy, llm_report, decision):
    """세 판단을 나란히 둔 기록. A단계에서 실제 전송(would_send)은 정책 규칙이 정한다."""
    llm_choice = (llm_report or {}).get("send_recommendation", {}).get("choice")
    return {"would_send": policy["choice"] == "send", "decided_by": "policy",
            "policy": policy["choice"], "mandatory": policy["mandatory"],
            "llm": llm_choice, "decision_model": decision["choice"],
            "decision_model_failed": decision["error"] is not None}
