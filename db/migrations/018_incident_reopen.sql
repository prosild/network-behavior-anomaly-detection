-- 018. 종료한 사건을 다시 여는 함수 dashboard.reopen_incident를 더한다(DD-022): closed → investigating.
--
-- 배경: 상태는 open → investigating → closed로 앞으로만 간다(008·009·012). 종료는 사람이 내린 결론이라, 뒤늦게 결론이
-- 틀렸다는 것을 알아도 고칠 방법이 없었다. 실제 관제처럼 종료한 건을 "확인 중"으로 다시 열고, 다시 조사해 새 결론으로 종료하게 한다.
-- 재개를 dashboard.transition_incident에 넣지 않고 함수를 따로 두는 이유:
--   transition_incident에는 "기대하는 지금 상태" 인자가 없다. 재개를 거기에 더하면 처음 조사 시작(open → investigating)과
--   재개(closed → investigating)가 같은 호출(p_to = 'investigating')이 된다. 그러면 A가 종료한 사건을, 아직 열림으로 보이는
--   B의 오래된 화면에서 "분석 시작"을 눌러 조용히 다시 열고 A의 결론을 지운다. 지금까지 거부되던 오래된 요청이다.
--   그래서 transition_incident(012 정의)는 그대로 두고, 재개는 "다시 열기"를 뜻하는 별도 호출로만 받는다.
-- 규칙(함수가 강제한다. 화면이나 호출하는 쪽을 믿지 않는다):
-- - 누가(actor)·왜(reason)는 필수(22023), 화면이 보던 작업에 그 사건이 있어야 한다(02000).
-- - 지금 상태가 closed일 때만 다시 연다. 열림(상태 행 없음 포함)·확인 중이면 거부한다(22023). 거부할 때 상태 행을 만들지 않는다.
-- - 기대 결론(p_expected_resolution, 선택): 화면이 보고 있던 종료 결론을 넣으면 지금 결론과 같을 때만 다시 연다(다르면 22023).
--   오래된 화면에 결론 A로 보이는 사이 다른 사람이 다시 열어 결론 B로 다시 종료했으면, 오래된 화면의 "다시 열기"가 B를
--   지우지 못하게 한다. NULL이면 상태만 본다. 세 결론 값(true_positive·false_positive·benign)이 아니면 22023.
-- - 다시 열면 상태 investigating, 결론 NULL(표의 CHECK: 종료일 때만 결론이 있다). 되돌린 결론은 앞선 종료 이력 행에 그대로 남는다.
--   이력에는 (closed → investigating, 결론 NULL, 누가, 왜) 한 행이 추가된다. 다시 종료는 transition_incident로 한다.
-- - 실행 권한은 dashboard_rw(대시보드)에만 준다. zeekad_worker에는 주지 않는다(파이프라인은 사건을 다시 열지 않는다).
-- - 소유자는 zeekad_owner로 고정한다(ALTER FUNCTION ... OWNER). 슈퍼유저로 이 파일을 실행해도 SECURITY DEFINER 함수가
--   슈퍼유저 권한으로 돌지 않고, 뒤에 db_migrate.py(zeekad_owner)가 다시 적용할 때 소유자 문제로 멈추지 않는다.
-- 바꾸지 않는 것: dashboard.transition_incident, 표, 뷰, 다른 권한.
-- 실행 계정: zeekad_owner. 가능하면 python scripts/db_migrate.py --db <DB>로 적용한다. psql로 따로 실행하면
--   schema_migrations에 기록이 남지 않아 다음 db_migrate가 한 번 더 적용한다(결과는 같다).
-- 선행 조건: 역할 dashboard_rw·zeekad_owner, migration 008·012까지 적용된 DB(incident_status의 키가 incident_id, last_job_id 열).
--   표를 바꾸지 않으므로 스냅샷 복원 DB에 이 파일 하나만 실행해도 된다.
--   CREATE OR REPLACE, ALTER ... OWNER, REVOKE·GRANT라 다시 실행해도 결과가 같다(멱등).
CREATE OR REPLACE FUNCTION dashboard.reopen_incident(p_job bigint, p_incident text, p_actor text, p_reason text,
                                                     p_expected_resolution text DEFAULT NULL)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = zeekad, pg_temp            -- 호출하는 쪽의 search_path로 다른 표를 끼워 넣지 못하게 고정한다
AS $$
DECLARE
    v_from       text;
    v_resolution text;
BEGIN
    IF coalesce(btrim(p_actor), '') = '' OR coalesce(btrim(p_reason), '') = '' THEN
        RAISE EXCEPTION '누가(actor)와 왜(reason)를 적어야 한다' USING ERRCODE = '22023';
    END IF;
    -- 화면이 보고 있던 작업에 그 사건이 있는지 확인한다(엉뚱한 사건 ID를 막는다). 상태는 사건 ID 하나에 붙는다.
    IF NOT EXISTS (SELECT 1 FROM incident WHERE job_id = p_job AND incident_id = p_incident) THEN
        RAISE EXCEPTION '사건이 없다: % %', p_job, p_incident USING ERRCODE = '02000';
    END IF;
    -- 같은 사건을 동시에 바꾸지 못하게 행을 잠근다. 행이 없으면 열림이다(만들지 않고 아래에서 거부한다)
    SELECT status, resolution INTO v_from, v_resolution FROM incident_status WHERE incident_id = p_incident FOR UPDATE;
    v_from := coalesce(v_from, 'open');
    IF v_from <> 'closed' THEN
        RAISE EXCEPTION '종료한 사건만 다시 열 수 있다. 지금 상태: %', v_from USING ERRCODE = '22023';
    END IF;
    -- 기대 결론은 잠근 행의 결론과 비교한다(그사이 다른 사람이 다시 열고 다른 결론으로 종료했으면 거부)
    IF p_expected_resolution IS NOT NULL THEN
        IF p_expected_resolution NOT IN ('true_positive', 'false_positive', 'benign') THEN
            RAISE EXCEPTION '기대 결론은 true_positive·false_positive·benign 중 하나다' USING ERRCODE = '22023';
        END IF;
        IF p_expected_resolution <> v_resolution THEN
            RAISE EXCEPTION '종료 결론이 화면과 다르다. 지금 결론: %', v_resolution USING ERRCODE = '22023';
        END IF;
    END IF;

    UPDATE incident_status SET status = 'investigating', resolution = NULL, updated_at = now(), updated_by = p_actor,
                               last_job_id = p_job
    WHERE incident_id = p_incident;
    INSERT INTO incident_status_history (job_id, incident_id, from_status, to_status, resolution, actor, reason)
    VALUES (p_job, p_incident, 'closed', 'investigating', NULL, p_actor, p_reason);
    RETURN 'investigating';
END
$$;

ALTER FUNCTION dashboard.reopen_incident(bigint, text, text, text, text) OWNER TO zeekad_owner;
-- 함수는 기본으로 누구나 실행할 수 있다(PUBLIC). 대시보드 계정만 남긴다.
REVOKE ALL ON FUNCTION dashboard.reopen_incident(bigint, text, text, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION dashboard.reopen_incident(bigint, text, text, text, text) TO dashboard_rw;
