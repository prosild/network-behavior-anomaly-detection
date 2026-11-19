"""ATT&CK 기법 문서를 임베딩해 rag.document_embedding에 넣는다(단계 5a-4).

- 글은 zeek_ad.rag.embedding_text(머리·설명·탐지 절)다. 글 해시가 DB와 같으면 다시 만들지 않는다.
- 밖으로 나가는 것은 공개 ATT&CK 문서뿐이다. API 키는 deploy/.env에서 읽고 출력하지 않는다.
예: python scripts/embed_attack_docs.py --model gemini
"""

import argparse
from pathlib import Path
import sys

from pgvector.psycopg import register_vector

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
from zeek_ad.db import connect, load_env  # noqa: E402
from zeek_ad.rag import GEMINI_DIMS, GEMINI_MODEL_ID, gemini_embed, load_corpus, text_sha256  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", choices=["gemini"], required=True)
    args = parser.parse_args()
    model_id, dims = GEMINI_MODEL_ID, GEMINI_DIMS

    with connect("zeekad_worker") as conn:
        register_vector(conn)
        ids, texts = load_corpus(conn)
        done = dict(conn.execute("SELECT attack_id, text_sha256 FROM rag.document_embedding WHERE model_id = %s",
                                 (model_id,)).fetchall())
    todo = [(i, t) for i, t in zip(ids, texts) if done.get(i) != text_sha256(t)]
    print(f"{model_id}: 문서 {len(ids)}개, 이미 있음 {len(ids) - len(todo)}개, 새로 만듦 {len(todo)}개")
    if not todo:
        return

    from google import genai
    client = genai.Client(api_key=load_env()["GEMINI_API_KEY"])
    vectors = gemini_embed(client, [t for _, t in todo], "RETRIEVAL_DOCUMENT")

    with connect("zeekad_worker") as conn:  # 한 트랜잭션: 중간에 실패하면 아무것도 남지 않는다
        register_vector(conn)
        with conn.cursor() as cur:
            cur.executemany(
                """INSERT INTO rag.document_embedding (attack_id, model_id, dims, text_sha256, embedding)
                   VALUES (%s, %s, %s, %s, %s)
                   ON CONFLICT (attack_id, model_id) DO UPDATE
                   SET dims = EXCLUDED.dims, text_sha256 = EXCLUDED.text_sha256,
                       embedding = EXCLUDED.embedding, created_at = now()""",
                [(i, model_id, dims, text_sha256(t), v) for (i, t), v in zip(todo, vectors)])
    print(f"넣음 {len(todo)}행")


if __name__ == "__main__":
    main()
