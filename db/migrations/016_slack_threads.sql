-- 016. 같은 자산 알림 묶음(DD-010 결정 5).
--
-- 같은 자산·역할의 미해결 알림이 60분 안에 있으면 새 사건 알림을 그 알림의 Slack 스레드 답글로 합친다.
-- 묶음 안에서 마지막으로 채널에 알린 지 30분이 지났으면 답글을 채널에도 띄운다(Slack reply_broadcast, 재알림).
-- 판단은 zeek_ad.slack.group_alert(관측 시각 기준)가 하고, 여기에는 결과만 남긴다. 조사 큐(사건)는 억제하지 않는다.
-- thread_parent: 이 알림이 답글로 붙는 묶음 머리 사건의 incident_id. 머리 알림 자신은 NULL.
--                실제 전송 때는 그 사건의 첫 알림 slack_ts를 thread_ts로 쓴다.
SET search_path = zeekad;

ALTER TABLE slack_delivery
    ADD COLUMN thread_parent   text,
    ADD COLUMN reply_broadcast boolean NOT NULL DEFAULT false;

-- 기존 열은 그대로 두고 뒤에 두 열을 더한다
CREATE OR REPLACE VIEW dashboard.slack_deliveries AS
SELECT s.job_id, s.incident_id,
       CASE WHEN s.report_version LIKE 'status:%' THEN 'status' ELSE 'incident' END AS zeekad_message_kind,
       s.report_version AS zeekad_message_version,
       s.mode AS zeekad_delivery_mode, s.status AS zeekad_delivery_status,
       s.payload AS slack_payload, s.slack_ts, s.delivered_at, s.error, s.created_at,
       s.thread_parent AS zeekad_thread_parent, s.reply_broadcast AS zeekad_reply_broadcast
FROM slack_delivery s
JOIN scoring_job j ON j.job_id = s.job_id AND j.status = 'succeeded';
