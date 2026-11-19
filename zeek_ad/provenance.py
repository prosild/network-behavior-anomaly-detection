"""manifest에 남길 파일 기록(경로·크기·해시) 도우미."""

import hashlib
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def project_path(path):
    # 프로젝트 안의 파일은 상대 경로로 남겨 다른 컴퓨터에서도 읽을 수 있게 한다.
    try:
        return Path(path).resolve().relative_to(PROJECT_ROOT).as_posix()
    except ValueError:
        return str(path)


def file_record(path):
    path = Path(path)
    return {"path": project_path(path), "size_bytes": path.stat().st_size, "sha256": sha256(path)}
