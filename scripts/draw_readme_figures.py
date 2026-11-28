"""README의 결과 그림 두 장을 그린다.

- docs/figures/eval-recall.png: 공개 데이터 평가. 하루 큐 상위 10·50건에 든 공격 에피소드 비율(큐별).
- docs/figures/lab-attacks.png: 실습망 공격 8종(13회)의 실행별 판정과 첫 알림까지 걸린 시간.

숫자는 이미 확정한 결과를 옮겨 적은 것이다(outputs/는 저장소에 없다).
- 평가: README "평가 결과"의 표. 원본은 outputs/eval/의 각 실행 metrics.json이다(단계 3 진행 기록).
- 실습망: docs/lab-attack-detection.md의 결과 표(2026-11-26 계산).
한글 글꼴(나눔바른고딕 또는 나눔고딕)이 있어야 한다. 실행: python scripts/draw_readme_figures.py
"""

from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib import font_manager  # noqa: E402
from matplotlib.patches import FancyBboxPatch  # noqa: E402

FIGURES = Path(__file__).resolve().parents[1] / "docs" / "figures"

# 색: 차트 지침의 기본 팔레트(범주 1·2번, 상태 색, 글자·축 색). 범주 두 색은 지침이 검증한 조합이다.
INK = "#191919"
INK2 = "#666666"
GRID = "#e7e7e7"
AXIS = "#c2c2c2"
AT10 = "#257de0"   # Recall@10
AT50 = "#f47230"   # Recall@50(흰 바탕 대비가 낮아 값 라벨을 늘 붙인다)
VERDICT = {        # 판정: 상태 색 + 글자. 색만으로 뜻을 전하지 않는다.
    "잡힘": "#0aac23",
    "구분 안 됨": "#fbb315",
    "후보만": "#f18a59",
    "놓침": "#dc3c3d",
}


def pick_font():
    """설치된 한글 글꼴 하나를 고른다(scripts/draw_architecture.py와 같다)."""
    for path in Path("/usr/share/fonts").rglob("Nanum*.ttf"):
        font_manager.fontManager.addfont(str(path))
    names = {f.name for f in font_manager.fontManager.ttflist}
    for name in ("NanumBarunGothic", "NanumGothic", "Noto Sans KR", "Malgun Gothic"):
        if name in names:
            return name
    raise SystemExit("한글 글꼴이 없다(나눔고딕 등)")


# 평가 결과: (큐 이름, @10 맞힌 수, @50 맞힌 수, 종류). 종류: main(결합), model, compare(비교), diag(진단 기준선)
CIC = [
    ("결합 v1(세 모델)", 8, 14, "main"),
    ("꼬리 희귀도 v2", 8, 13, "model"),
    ("Transformer v2", 8, 11, "model"),
    ("TGN", 11, 13, "model"),
    ("Isolation Forest v2", 4, 13, "compare"),
    ("NAT 주소와의 연결 수", 12, 13, "diag"),
]
SYNTHETIC = [
    ("결합 v1(세 모델)", 5, 13, "main"),
    ("꼬리 희귀도 v2", 7, 11, "model"),
    ("Transformer v2", 4, 11, "model"),
    ("TGN", 2, 9, "model"),
]
TAGS = {"compare": "비교용", "diag": "진단용 기준선"}


def recall_panel(ax, rows, total, title):
    """큐마다 @10(파랑)과 @50(주황)을 선으로 잇는다. 값 라벨은 맞힌 수/전체."""
    n = len(rows)
    for i, (name, hit10, hit50, kind) in enumerate(rows):
        y = n - 1 - i
        x10, x50 = 100 * hit10 / total, 100 * hit50 / total
        ax.plot([x10, x50], [y, y], color=AXIS, linewidth=2, zorder=1, solid_capstyle="round")
        ax.scatter([x10], [y], s=90, color=AT10, edgecolor="white", linewidth=2, zorder=3)
        ax.scatter([x50], [y], s=90, color=AT50, edgecolor="white", linewidth=2, zorder=3)
        # 두 점이 가까우면 라벨을 점의 왼쪽·오른쪽에 둔다(같은 행에 붙어 보이게)
        if abs(x50 - x10) < 9:
            ax.text(x10 - 2.2, y, f"{hit10}", ha="right", va="center", fontsize=10, color=INK)
            ax.text(x50 + 2.2, y, f"{hit50}", ha="left", va="center", fontsize=10, color=INK)
        else:
            ax.text(x10, y + 0.3, f"{hit10}", ha="center", va="bottom", fontsize=10, color=INK)
            ax.text(x50, y + 0.3, f"{hit50}", ha="center", va="bottom", fontsize=10, color=INK)
        label = name if kind not in TAGS else f"{name}\n({TAGS[kind]})"
        ax.text(-3, y, label, ha="right", va="center", fontsize=11.5 if kind == "main" else 11,
                fontweight="bold" if kind == "main" else "normal",
                color=INK if kind in ("main", "model") else INK2)
    ax.set_xlim(0, 100)
    ax.set_ylim(-0.7, n - 0.3)
    ax.set_yticks([])
    ax.set_xticks([0, 25, 50, 75, 100])
    ax.set_xticklabels(["0", "25", "50", "75", "100%"], fontsize=10, color=INK2)
    ax.grid(axis="x", color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)
    for side in ("top", "right", "left"):
        ax.spines[side].set_visible(False)
    ax.spines["bottom"].set_color(AXIS)
    ax.tick_params(axis="x", length=0)
    ax.set_title(title, loc="left", fontsize=13, fontweight="bold", color=INK, pad=10)


def draw_eval(font):
    fig, (left, right) = plt.subplots(1, 2, figsize=(12.5, 4.9),
                                      gridspec_kw={"width_ratios": [1, 1], "wspace": 0.55})
    recall_panel(left, CIC, 16, "CIC-IDS-2017 화~금 · 확정 공격 16건")
    recall_panel(right, SYNTHETIC, 20, "합성 패턴 · 20건")
    fig.suptitle("하루 조사 큐 상위 N건 안에 든 공격 에피소드", x=0.035, ha="left", y=0.995,
                 fontsize=15, fontweight="bold", color=INK)
    handles = [plt.Line2D([], [], marker="o", linestyle="", markersize=9, color=AT10, label="상위 10건"),
               plt.Line2D([], [], marker="o", linestyle="", markersize=9, color=AT50, label="상위 50건")]
    fig.legend(handles=handles, loc="upper left", bbox_to_anchor=(0.03, 0.935), ncol=2, frameon=False,
               fontsize=11, handletextpad=0.3, columnspacing=1.2, labelcolor=INK)
    fig.text(0.035, 0.015, "숫자는 잡은 에피소드 수다. 표본이 16·20건이라 행동 모델(꼬리 희귀도·Transformer·TGN·결합) 사이의 95% 구간이 모두 겹친다. "
             "\nNAT 기준선은 CIC 공격이 NAT 주소로 들어오는 구조에 기댄 진단용이다. v2는 특징 버전, 결합 v1은 평가 때의 결합 규칙이다.",
             fontsize=9.5, color=INK2, ha="left", va="bottom", linespacing=1.5)
    fig.subplots_adjust(left=0.2, right=0.98, top=0.8, bottom=0.17)
    out = FIGURES / "eval-recall.png"
    fig.savefig(out, dpi=200, facecolor="white")
    plt.close(fig)
    return out


# 실습망: (공격, 창에 남는 모양, [(판정, 규칙 뒤 여부, 첫 알림까지 분 또는 None)], 묶음)
LAB = [
    ("빠른 스캔", "포트 1,000개로 퍼짐", [("잡힘", False, 7.0), ("잡힘", False, 15.2)], "spread"),
    ("서비스 스캔", "포트 200개와 버전 확인", [("잡힘", False, 6.8), ("잡힘", False, 10.2)], "spread"),
    ("느린 스캔", "5초에 포트 하나", [("잡힘", False, 6.9)], "spread"),
    ("공유 탐색", "내부 주소 4개의 SMB 공유 조회", [("잡힘", False, 3.6)], "spread"),
    ("분할 유출", "5분마다 4MB씩 3회", [("후보만", False, None), ("잡힘", True, 7.5)], "quiet"),
    ("비커닝", "한 상대에 작은 연결을 규칙적으로",
     [("구분 안 됨", False, None), ("후보만", False, None), ("구분 안 됨", True, None)], "quiet"),
    ("DNS 터널", "긴 이름의 DNS 질의 다수", [("후보만", False, None)], "quiet"),
    ("무차별 대입", "SSH 한 포트에 연결 수백", [("놓침", False, None)], "quiet"),
]


def chip(ax, x, y, w, h, verdict, after_rule):
    """판정 칩: 옅은 상태 색 바탕 + 상태 색 테두리 + 진한 글자. 규칙 뒤 실행은 점선 테두리."""
    color = VERDICT[verdict]
    ax.add_patch(FancyBboxPatch((x, y - h / 2), w, h, boxstyle="round,pad=0,rounding_size=0.14",
                                facecolor=color + "33", edgecolor=color, linewidth=1.6,
                                linestyle=(0, (3, 2)) if after_rule else "solid"))
    text = verdict if not after_rule else f"{verdict}·규칙 뒤"
    ax.text(x + w / 2, y, text, ha="center", va="center", fontsize=9.6, color=INK)


def draw_lab(font):
    fig = plt.figure(figsize=(12.5, 6.0))
    names = fig.add_axes([0.0, 0.2, 0.26, 0.7])
    chips = fig.add_axes([0.27, 0.2, 0.36, 0.7], sharey=names)
    times = fig.add_axes([0.66, 0.2, 0.31, 0.7], sharey=names)
    n = len(LAB)
    # 묶음 사이에 틈을 둔다: 퍼지는 공격 4개 위, 한 상대에 몰리는 공격 4개 아래
    ys = [n - i + (0.6 if kind == "spread" else 0) for i, (_, _, _, kind) in enumerate(LAB)]
    for ax in (names, chips):
        ax.set_xlim(0, 1)
        ax.axis("off")
    chips.set_xlim(0, 3.25)
    for y, (name, shape, runs, _) in zip(ys, LAB):
        names.text(0.97, y + 0.13, name, ha="right", va="center", fontsize=12, fontweight="bold", color=INK)
        names.text(0.97, y - 0.22, shape, ha="right", va="center", fontsize=9.6, color=INK2)
        for j, (verdict, after_rule, minutes) in enumerate(runs):
            chip(chips, 0.05 + j * 1.07, y, 1.0, 0.56, verdict, after_rule)
            if minutes is not None:
                times.scatter([minutes], [y], s=80, color=VERDICT["잡힘"], edgecolor="white", linewidth=1.8,
                              zorder=3)
                times.text(minutes, y + 0.27, f"{minutes:.1f}", ha="center", va="bottom", fontsize=9.6, color=INK)
        if all(m is None for _, _, m in runs):
            times.text(0.3, y, "잡은 실행 없음", ha="left", va="center", fontsize=9.6, color=INK2)
    group_y = (ys[3] + ys[4]) / 2
    names.text(0.03, ys[0] + 0.75, "퍼지는 공격", ha="left", fontsize=10.5, color=INK2, fontweight="bold")
    names.text(0.03, group_y - 0.38, "한 상대에 몰리는 공격", ha="left", fontsize=10.5, color=INK2, fontweight="bold")
    for ax in (names, chips, times):
        ax.axhline(group_y, color=GRID, linewidth=1, xmin=0, xmax=1)
    chips.text(0.05, ys[0] + 0.75, "실행마다 판정", ha="left", fontsize=10.5, color=INK2, fontweight="bold")
    times.set_xlim(0, 17)
    times.set_ylim(min(ys) - 0.7, max(ys) + 1.0)
    times.set_yticks([])
    times.set_xticks([0, 5, 10, 15])
    times.set_xticklabels(["0", "5", "10", "15분"], fontsize=10, color=INK2)
    times.grid(axis="x", color=GRID, linewidth=0.8)
    times.set_axisbelow(True)
    for side in ("top", "right", "left"):
        times.spines[side].set_visible(False)
    times.spines["bottom"].set_color(AXIS)
    times.tick_params(axis="x", length=0)
    times.text(0, ys[0] + 0.75, "잡힌 실행의 첫 공격 연결 → 첫 알림", ha="left", fontsize=10.5, color=INK2,
               fontweight="bold")
    fig.suptitle("실습망 공격 8종(13회): 무엇을 잡았고 얼마나 걸렸나", x=0.02, ha="left", y=0.985,
                 fontsize=15, fontweight="bold", color=INK)
    fig.text(0.02, 0.015, "잡힘 = 공격 창에서 알림이 나갔고 평소보다 높은 모델이 있음 · 구분 안 됨 = 알림은 나갔지만 평소와 같음 · "
             "후보만 = 모델 후보였지만 알림 없음 · 놓침 = 어느 모델도 후보로 꼽지 않음.\n"
             "점선 칩은 브로드캐스트 오탐을 없앤 뒤 다시 돌린 실행이다. 종류마다 1~3회라 탐지율이 아니다.",
             fontsize=9.2, color=INK2, ha="left", va="bottom", linespacing=1.5)
    out = FIGURES / "lab-attacks.png"
    fig.savefig(out, dpi=200, facecolor="white")
    plt.close(fig)
    return out


def main():
    font = pick_font()
    plt.rcParams["font.family"] = font
    plt.rcParams["axes.unicode_minus"] = False
    for out in (draw_eval(font), draw_lab(font)):
        print(out.relative_to(FIGURES.parents[1]))


if __name__ == "__main__":
    main()
