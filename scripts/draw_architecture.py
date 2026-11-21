"""README 구조도(docs/figures/architecture.png)를 그린다.

위 줄은 공개 데이터로 모델을 만드는 흐름, 아래 두 줄은 실습망 실제 트래픽을 처리하는 흐름이다.
한글 글꼴(나눔바른고딕 또는 나눔고딕)이 있어야 한다. 실행: python scripts/draw_architecture.py
"""

from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib import font_manager  # noqa: E402
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch  # noqa: E402

OUT = Path(__file__).resolve().parents[1] / "docs" / "figures" / "architecture.png"

# 색: 단계별로 옅은 바탕 + 진한 테두리. 흑백으로 인쇄해도 글자가 읽히게 대비를 둔다.
COLORS = {
    "build": ("#EEF3FB", "#3B6BB5"),     # 모델 만들기
    "lab": ("#F3F7EE", "#4E8A3A"),       # 수집·처리
    "model": ("#FFF6E8", "#C47F17"),     # 채점
    "agent": ("#F6EEF8", "#8A4BA0"),     # 에이전트·알림
    "store": ("#F1F1F1", "#555555"),     # 저장·조회
}


def pick_font():
    """설치된 한글 글꼴 하나를 고른다. matplotlib 글꼴 캐시가 설치보다 오래됐을 수 있어 시스템 경로도 등록한다."""
    for path in Path("/usr/share/fonts").rglob("Nanum*.ttf"):
        font_manager.fontManager.addfont(str(path))
    names = {f.name for f in font_manager.fontManager.ttflist}
    for name in ("NanumBarunGothic", "NanumGothic", "Noto Sans KR", "Malgun Gothic"):
        if name in names:
            return name
    raise SystemExit("한글 글꼴이 없다(나눔고딕 등)")


def box(ax, x, y, w, h, text, kind, size=12.5, bold_first=True):
    """둥근 상자와 글자. 첫 줄은 굵게, 둘째 줄부터는 보통 굵기로 쓴다."""
    face, edge = COLORS[kind]
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.02,rounding_size=0.12",
                                linewidth=1.6, edgecolor=edge, facecolor=face))
    lines = text.split("\n")
    n = len(lines)
    step = 0.27
    top = y + h / 2 + step * (n - 1) / 2
    for i, line in enumerate(lines):
        ax.text(x + w / 2, top - i * step, line, ha="center", va="center",
                fontsize=size if i == 0 else size - 1.5,
                fontweight="bold" if (i == 0 and bold_first) else "normal",
                color="#222222" if i == 0 else "#444444")


def arrow(ax, start, end, style="-|>", dashed=False, color="#555555"):
    ax.add_patch(FancyArrowPatch(start, end, arrowstyle=style, mutation_scale=16, linewidth=1.6,
                                 color=color, linestyle=(0, (4, 3)) if dashed else "solid",
                                 shrinkA=2, shrinkB=2))


def lane_title(ax, x, y, text, color):
    ax.text(x, y, text, ha="left", va="center", fontsize=13.5, fontweight="bold", color=color)


def main():
    plt.rcParams["font.family"] = pick_font()
    fig, ax = plt.subplots(figsize=(13, 7.6), dpi=160)
    ax.set_xlim(0, 13)
    ax.set_ylim(0, 7.6)
    ax.axis("off")

    h = 0.95
    # 1. 모델 만들기(공개 데이터)
    lane_title(ax, 0.2, 7.25, "모델 만들기  ·  공개 데이터 CIC-IDS-2017", COLORS["build"][1])
    y1 = 5.95
    xs = [0.2, 2.65, 5.1, 7.65, 10.35]
    ws = [2.15, 2.15, 2.25, 2.4, 2.45]
    texts = ["PCAP 5일\n원본 패킷", "Zeek\nconn·dns·http·ssl…",
             "Silver → Gold\n5분 창 · 이벤트 그래프", "월요일 정상으로 학습\n화~금 · 합성 APT로 평가",
             "MLflow Registry\n배포 묶음(모델+설정)"]
    for x, w, t in zip(xs, ws, texts):
        box(ax, x, y1, w, h, t, "build")
    for i in range(4):
        arrow(ax, (xs[i] + ws[i], y1 + h / 2), (xs[i + 1], y1 + h / 2))

    # 2. 실제 트래픽 처리(실습망)
    lane_title(ax, 0.2, 5.35, "실제 트래픽 처리  ·  VMware 격리 실습망의 배포 VM", COLORS["lab"][1])
    y2 = 4.05
    xs2 = [0.2, 2.65, 5.1, 7.65, 10.35]
    ws2 = [2.15, 2.15, 2.25, 2.4, 2.45]
    texts2 = ["Kali 공격\n+ 정상 배경 재생", "tcpdump\n5분마다 파일", "Zeek\n파일이 오면 바로",
              "그날 다시 계산(Spark)\nSilver → Gold → 그래프", "세 모델 채점"]
    kinds2 = ["lab", "lab", "lab", "lab", "model"]
    for x, w, t, k in zip(xs2, ws2, texts2, kinds2):
        box(ax, x, y2, w, h, t, k)
    for i in range(4):
        arrow(ax, (xs2[i] + ws2[i], y2 + h / 2), (xs2[i + 1], y2 + h / 2))
    # 배포 묶음 → 채점(같은 계산을 운영에서 그대로 쓴다)
    arrow(ax, (10.35 + 2.45 / 2, y1), (10.35 + 2.45 / 2, y2 + h), dashed=True, color=COLORS["build"][1])
    ax.text(10.35 + 2.45 / 2 + 0.08, (y1 + y2 + h) / 2, "버전 고정", fontsize=10.5,
            color=COLORS["build"][1], va="center")

    # 세 모델 설명(채점 상자 아래)
    y3 = 2.45
    box(ax, 7.65, y3, 5.15, 1.05,
        "꼬리 희귀도 · Transformer · TGN\n점 이상 · 문맥적 이상 · 관계적 이상 → 결합 큐",
        "model", size=12)
    arrow(ax, (10.35 + 2.45 / 2, y2), (10.35 + 2.45 / 2, y3 + 1.05))

    # 3. 조사·알림
    box(ax, 4.2, y3, 3.0, 1.05, "PostgreSQL\n조사 큐 · 근거 · 상태", "store", size=12)
    arrow(ax, (7.65, y3 + 0.52), (7.2, y3 + 0.52))
    box(ax, 0.2, y3, 3.55, 1.05, "Java 관리자 대시보드\n조사 큐 · 보고서 · 검토 결정", "store", size=12)
    arrow(ax, (4.2, y3 + 0.62), (3.75, y3 + 0.62))
    arrow(ax, (3.75, y3 + 0.38), (4.2, y3 + 0.38))

    y4 = 0.55
    box(ax, 2.0, y4, 6.6, 1.15,
        "LangGraph 에이전트(사건마다)\n근거 → ATT&CK 검색(RAG) → LLM 보고서 → 숫자 검증 → 판단 → 분석가 검토",
        "agent", size=12)
    box(ax, 9.25, y4, 3.55, 1.15, "Slack 알림(dry-run)\n같은 자산은 스레드로 묶음", "agent", size=12)
    arrow(ax, (5.7, y3), (5.7, y4 + 1.15), style="<|-|>")
    arrow(ax, (8.6, y4 + 0.57), (9.25, y4 + 0.57))
    ax.text(0.2, 0.18, "LLM에는 실제 IP 대신 가명과 허용된 수치만 보낸다. 탐지와 순위는 모델이 정하고 LLM은 설명만 한다.",
            fontsize=10.5, color="#555555", va="center")

    OUT.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(OUT, bbox_inches="tight", facecolor="white")
    print(f"저장: {OUT}")


if __name__ == "__main__":
    main()
