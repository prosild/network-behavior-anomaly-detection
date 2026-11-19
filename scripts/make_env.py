"""deploy/.env를 무작위 비밀번호로 만든다. 이미 있으면 덮어쓰지 않는다(DB가 그 비밀번호로 초기화돼 있다)."""

from pathlib import Path
import secrets

PROJECT_ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = PROJECT_ROOT / "deploy" / ".env.example"
OUT = PROJECT_ROOT / "deploy" / ".env"


def main():
    if OUT.exists():
        raise SystemExit(f"이미 있다: {OUT}")
    lines = []
    for line in EXAMPLE.read_text(encoding="utf-8").splitlines():
        if line.endswith("=change-me"):
            line = line.replace("change-me", secrets.token_urlsafe(24))  # 셸·URL에 안전한 문자만 쓴다
        lines.append(line)
    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    OUT.chmod(0o600)  # 소유자만 읽는다
    print(f"만들었다: {OUT}")


if __name__ == "__main__":
    main()
