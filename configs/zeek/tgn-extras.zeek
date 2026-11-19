# run.v2 추가 설정(DD-007). v1의 write-ts.zeek 동작은 바꾸지 않는다.
#
# 1) conn.log에 community_id를 붙인다. 다른 도구(Suricata 등)와 같은 연결을 맞출 때 쓰는 표준 해시다.
# 2) ftp.log에 USER·PASS 명령도 남긴다. 기본값은 파일 전송 명령만 남겨서 로그인 시도가 보이지 않는다.
#    비밀번호는 기본 설정대로 <hidden>으로 가려진다. 응답 코드(예: 530 로그인 실패)는 같은 행에 남는다.

@load policy/protocols/conn/community-id-logging

redef FTP::logged_commands += { "USER", "PASS" };
