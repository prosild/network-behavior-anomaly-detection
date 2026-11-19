"""근거 조회 API를 띄운다. 기본은 이 PC 안에서만 접속한다: http://127.0.0.1:8000/docs. 끌 때는 Ctrl+C.

컨테이너(Compose, DD-015)에서는 --host 0.0.0.0으로 컨테이너 네트워크에 연다. 바깥에 어디까지 보일지는
Compose의 ports(127.0.0.1로 묶음)가 정한다.
"""

import argparse
from pathlib import Path
import sys

import uvicorn

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    uvicorn.run("zeek_ad.api:app", host=args.host, port=args.port)
