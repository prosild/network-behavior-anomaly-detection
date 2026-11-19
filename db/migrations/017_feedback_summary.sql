-- 017. 분석가 결론 집계(Q61): 라벨 없는 운영에서 쌓이는 유일한 라벨(사건 종료 결론)로 알림의 정밀도를 본다.
--
-- 캡처의 최신 큐(dashboard.latest_incident_queue) 사건마다 "Slack으로 알렸는가"와 "종료 결론"을 붙여
-- 캡처 × 묶음 버전 × 처음 뽑은 모델로 집계한다. zeekad_picked_by = 'all'은 그 캡처·묶음 전체다.
-- - 정밀도 = 실제 공격(true_positive) ÷ 결론 난 사건. benign(이상하지만 정상 업무)은 공격이 아닌 쪽에 센다.
-- - 결론 난 사건이 적으면 정밀도는 믿기 어렵다. 알린 사건 중 결론 난 비율(zeekad_alert_resolved_rate)을 같이 본다.
-- - 놓친 공격(재현율)은 이 집계로 알 수 없다. 큐에 오르지 않은 공격에는 결론이 생기지 않는다.
SET search_path = zeekad;

CREATE VIEW dashboard.feedback_summary AS
WITH q AS (
    SELECT l.capture_id, l.bundle_id, l.zeekad_picked_by, l.zeekad_resolution,
           EXISTS (SELECT 1 FROM slack_delivery d WHERE d.incident_id = l.incident_id
                   AND d.report_version NOT LIKE 'status:%') AS alerted
    FROM dashboard.latest_incident_queue l
)
SELECT capture_id, bundle_id,
       CASE WHEN GROUPING(zeekad_picked_by) = 1 THEN 'all' ELSE zeekad_picked_by END AS zeekad_picked_by,
       count(*) AS incidents,
       count(*) FILTER (WHERE alerted) AS alerted,
       count(*) FILTER (WHERE zeekad_resolution IS NOT NULL) AS resolved,
       count(*) FILTER (WHERE zeekad_resolution = 'true_positive') AS true_positive,
       count(*) FILTER (WHERE zeekad_resolution = 'false_positive') AS false_positive,
       count(*) FILTER (WHERE zeekad_resolution = 'benign') AS benign,
       round(count(*) FILTER (WHERE zeekad_resolution = 'true_positive')::numeric
             / nullif(count(*) FILTER (WHERE zeekad_resolution IS NOT NULL), 0), 3) AS zeekad_precision,
       round(count(*) FILTER (WHERE alerted AND zeekad_resolution = 'true_positive')::numeric
             / nullif(count(*) FILTER (WHERE alerted AND zeekad_resolution IS NOT NULL), 0), 3) AS zeekad_alert_precision,
       round(count(*) FILTER (WHERE alerted AND zeekad_resolution IS NOT NULL)::numeric
             / nullif(count(*) FILTER (WHERE alerted), 0), 3) AS zeekad_alert_resolved_rate
FROM q
GROUP BY GROUPING SETS ((capture_id, bundle_id, zeekad_picked_by), (capture_id, bundle_id));

GRANT SELECT ON dashboard.feedback_summary TO dashboard_ro, zeekad_api;
