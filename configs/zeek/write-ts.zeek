# Zeek 로그를 JSON으로 쓰고, 모든 로그 행에 _write_ts 필드를 붙인다.
#
# _write_ts는 그 행을 기록하는 순간의 network_time()이다.
# PCAP을 읽을 때 network_time()은 마지막으로 처리한 패킷의 시각이다.
# 벽시계 시각이나 디스크에 쓴 시각이 아니다(최종 설계 4.1절).
#
# 과거 검증의 historical/design-verification-2026-11-03/zs/ext.zeek와 동작이 같다.
# 과거 결과를 재현하려고 v1은 동작을 바꾸지 않는다. 이름만 읽기 쉽게 바꿨다.

redef LogAscii::use_json = T;

type WriteTsExtension: record {
    write_ts: time &log;
};

function add_write_ts(path: string): WriteTsExtension
    {
    return WriteTsExtension($write_ts = network_time());
    }

# 확장 필드에는 Log::default_ext_prefix("_")가 붙어 로그에서는 _write_ts가 된다.
redef Log::default_ext_func = add_write_ts;
