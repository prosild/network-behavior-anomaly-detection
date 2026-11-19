"""2단계 EDA: 편향 진단(NAT·동점 포화·긴 연결)과 모델·결합 비교 근거를 표준 seaborn 한글 차트로 시각화한다.

입력(읽기 전용):
- outputs/eval/_summary/summary-20261106T072759Z.json
- outputs/eval/20261106T072530Z-tail_rarity_v2/metrics.json
- outputs/eval/20261108T120813Z-synthetic_apt_v1/metrics.json
- outputs/eval/20261110T104214Z-tgn_recon/{metrics.json, no_nat.json}
- outputs/eval/20261110T104445Z-synthetic_apt_v1/metrics.json
- outputs/eval/20261111T014619Z-fusion_v1/metrics.json
- outputs/diagnostics/long_connections.json

출력(outputs/eda/):
- 04_bias_and_tie_diagnostics.png
- 05_model_recall_comparison.png
- 06_synthetic_pattern_heatmap.png
- part2_stats.json
"""

import argparse
import json
from pathlib import Path
import sys

from matplotlib.colors import ListedColormap
import matplotlib.patches as mpatches
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
from zeek_ad import eda_plots  # noqa: E402
from zeek_ad.eda_plots import setup_style  # noqa: E402
from zeek_ad.provenance import file_record, project_path  # noqa: E402

CIC_DAYS = ["cic17-tue", "cic17-wed", "cic17-thu", "cic17-fri"]
CIC_DAY_LABELS = {
    "cic17-tue": "화요일\n(2건)",
    "cic17-wed": "수요일\n(5건)",
    "cic17-thu": "목요일\n(6건)",
    "cic17-fri": "금요일\n(3건)",
}
SYN_DAYS = ["syn1-tue", "syn1-wed", "syn1-thu", "syn1-fri"]
PATTERNS = [
    ("internal_scan", "internal_scan\n(내부 정찰)"),
    ("lateral_smb", "lateral_smb\n(측면 이동)"),
    ("slow_exfil", "slow_exfil\n(느린 유출)"),
    ("dns_tunnel", "dns_tunnel\n(DNS 터널)"),
    ("beacon_https", "beacon_https\n(HTTPS 비콘)"),
]


def load_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def entry_from_summary(block, k):
    """summary JSON의 pooled[k] 항목에서 recall·신뢰구간·건수를 꺼낸다."""
    p = block["pooled"][str(k)]
    return {
        "matched": int(p["matched"]),
        "episodes": int(p["episodes"]),
        "recall": float(p["recall"]),
        "low": float(p["low"]),
        "high": float(p["high"]),
    }


def entry_from_metrics(pooled_dict, k):
    """metrics.json의 pooled[k] 항목에서 recall·신뢰구간·건수를 꺼낸다."""
    p = pooled_dict[str(k)]
    ci = p["ci"]
    return {
        "matched": int(p["matched"]),
        "episodes": int(p["episodes"]),
        "recall": float(ci["recall"]),
        "low": float(ci["low"]),
        "high": float(ci["high"]),
    }


def plot_bias_and_tie(summary, tail_v2, tgn_metrics, tgn_no_nat, long_conn, out_path):
    """차트 4: CIC NAT 편향과 꼬리 희귀도 v2 동점 민감도·긴 연결 진단을 표준 seaborn 막대 차트로 그린다."""
    fig, (ax1, ax2) = plt.subplots(
        1,
        2,
        figsize=(16.2, 7.0),
        width_ratios=[1.18, 1.0],
    )

    # 왼쪽: 모델 vs NAT 진단 기준선 (표준 seaborn 수평 그룹 막대)
    nat_rows = [
        ("IF v2", entry_from_summary(summary["iforest_v2"], 10), entry_from_summary(summary["iforest_v2"], 50)),
        ("Transformer v2", entry_from_summary(summary["transformer_v2"], 10), entry_from_summary(summary["transformer_v2"], 50)),
        ("꼬리 희귀도 v2", entry_from_summary(summary["tail_rarity_v2"], 10), entry_from_summary(summary["tail_rarity_v2"], 50)),
        ("TGN recon (전체)", entry_from_metrics(tgn_metrics["pooled"], 10), entry_from_metrics(tgn_metrics["pooled"], 50)),
        ("TGN recon (NAT 제외)", entry_from_metrics(tgn_no_nat["pooled"], 10), entry_from_metrics(tgn_no_nat["pooled"], 50)),
        ("NAT 유무 (진단용)", entry_from_summary(summary["nat_presence"], 10), entry_from_summary(summary["nat_presence"], 50)),
        ("NAT 연결 수 (진단용)", entry_from_summary(summary["nat_count"], 10), entry_from_summary(summary["nat_count"], 50)),
    ]

    df_nat_rows = []
    for label, m10, m50 in nat_rows:
        df_nat_rows.append({"구분": label, "지표": "Recall@10", "Recall(%)": m10["recall"] * 100})
        df_nat_rows.append({"구분": label, "지표": "Recall@50", "Recall(%)": m50["recall"] * 100})
    df_nat = pd.DataFrame(df_nat_rows)

    sns.barplot(data=df_nat, y="구분", x="Recall(%)", hue="지표", orient="h", ax=ax1, edgecolor="white", linewidth=0.6)
    ax1.axhline(4.5, color="#94a3b8", linestyle="--", linewidth=1.1, zorder=1)

    for container, col_idx in [(ax1.containers[0], 1), (ax1.containers[1], 2)]:
        for bar, row in zip(container, nat_rows):
            m = row[col_idx]
            val = m["recall"] * 100
            cy = bar.get_y() + bar.get_height() / 2
            ax1.text(val + 1.4, cy, f"{val:.0f}% ({m['matched']}/{m['episodes']})",
                     va="center", ha="left", fontsize=8.4, color="#334155")

    for tick, (label, _, _) in zip(ax1.get_yticklabels(), nat_rows):
        if "진단용" in label:
            tick.set_color("#b45309")
            tick.set_fontweight(eda_plots.BOLD_WEIGHT)
        elif "NAT 제외" in label:
            tick.set_color("#5b21b6")
            tick.set_fontweight(eda_plots.BOLD_WEIGHT)

    ax1.set_xlim(0, 110)
    ax1.set_xticks([0, 25, 50, 75, 100])
    ax1.set_ylabel("")
    ax1.set_xlabel("CIC 회고 평가 Recall (%) — 전체 16건")
    ax1.set_title("CIC 평가의 NAT(172.16.0.1) 편향 진단", loc="left", pad=30)
    ax1.legend(title=None, loc="lower left", bbox_to_anchor=(0.0, 1.01), ncol=2, frameon=False, fontsize=9.4)
    sns.despine(ax=ax1)

    # 오른쪽: 꼬리 희귀도 v2 경계 동점 민감도 (고정 순서 vs 무작위 1,000회 평균 + 최소~최대 범위)
    fixed_vals, means, mins, maxs, tie_sizes = [], [], [], [], []
    tie_records = {}
    tie_df_rows = []
    for d in CIC_DAYS:
        day_info = tail_v2["days"][d]
        fixed = float(day_info["recall"]["10"]["recall"])
        ts = day_info["tie_sensitivity"]["10"]
        rec = ts["recall"]
        mean_v, min_v, max_v, tie_n = float(rec["mean"]), float(rec["min"]), float(rec["max"]), int(ts["tie_size"])
        fixed_vals.append(fixed)
        means.append(mean_v)
        mins.append(min_v)
        maxs.append(max_v)
        tie_sizes.append(tie_n)
        tie_records[d] = {
            "fixed_recall_10": fixed,
            "tie_size_at_10": tie_n,
            "mean": mean_v,
            "min": min_v,
            "max": max_v,
        }
        day_lbl = CIC_DAY_LABELS[d]
        tie_df_rows.append({"요일": day_lbl, "순위 기준": "고정 해시 @10", "Recall@10(%)": fixed * 100})
        tie_df_rows.append({"요일": day_lbl, "순위 기준": "무작위 1,000회 평균 [최소~최대]", "Recall@10(%)": mean_v * 100})

    df_tie = pd.DataFrame(tie_df_rows)
    sns.barplot(data=df_tie, x="요일", y="Recall@10(%)", hue="순위 기준", ax=ax2, edgecolor="white", linewidth=0.6)

    if ax2.containers:
        ax2.bar_label(ax2.containers[0], fmt="%.0f%%", padding=3, fontsize=8.8, color="#334155")

    means_pct = np.array(means) * 100
    mins_pct = np.array(mins) * 100
    maxs_pct = np.array(maxs) * 100
    fixed_pct = np.array(fixed_vals) * 100

    for i, bar in enumerate(ax2.containers[1]):
        bx = bar.get_x() + bar.get_width() / 2
        lo = max(0.0, means_pct[i] - mins_pct[i])
        hi = max(0.0, maxs_pct[i] - means_pct[i])
        ax2.errorbar([bx], [means_pct[i]], yerr=np.array([[lo], [hi]]),
                     fmt="none", ecolor="#1e293b", elinewidth=1.6, capsize=4.5, zorder=4)
        top_bar1 = max(means_pct[i], maxs_pct[i])
        ax2.text(bx, top_bar1 + 2.5, f"평균 {means_pct[i]:.0f}%",
                 ha="center", va="bottom", fontsize=8.6, color="#334155")

        top_day = max(fixed_pct[i], top_bar1)
        ax2.text(
            i,
            top_day + 12.5,
            f"동점 {tie_sizes[i]}건",
            ha="center",
            va="bottom",
            fontsize=9.0,
            color="#991b1b",
            fontweight=eda_plots.BOLD_WEIGHT,
            bbox={"boxstyle": "round,pad=0.25", "facecolor": "#fee2e2", "edgecolor": "#fca5a5", "linewidth": 0.8},
        )

    ax2.set_ylim(0, 134)
    ax2.set_yticks([0, 25, 50, 75, 100])
    ax2.set_xlabel("")
    ax2.set_ylabel("요일별 Recall@10 (%)")
    ax2.set_title("꼬리 희귀도 v2 동점 민감도 (포화값 log(1287)=7.16)", loc="left", pad=30)
    ax2.legend(title=None, loc="lower left", bbox_to_anchor=(-0.02, 1.01), ncol=2, frameon=False, fontsize=9.0)
    sns.despine(ax=ax2)

    fig.suptitle(
        "NAT 편향이 크고 TGN도 NAT 연결을 빼면 크게 떨어지며(일부는 남음), 꼬리 희귀도는 동점 포화 한계가 뚜렷함",
        y=0.965,
        fontweight=eda_plots.BOLD_WEIGHT,
    )
    fig.text(
        0.5,
        0.905,
        "단순 NAT 규칙만으로도 상위권이 높게 나오는 편향을 확인했으며, 1,000회 무작위 동점 해소 시 수·목요일 재현율이 크게 흔들림",
        ha="center",
        va="center",
        fontsize=10.3,
        color="#475569",
    )

    lc_summary = (
        f"300초 초과 긴 연결 지배 창 비율(월요일 보류 312창 기준): 전체 {long_conn['iforest_v2']['long_dominated_share_all']*100:.1f}%  |  "
        f"상위 10 창 비율 — IF v2 {long_conn['iforest_v2']['top10_long_dominated_share']*100:.0f}%, "
        f"꼬리 v2 {long_conn['tail_rarity_v2']['top10_long_dominated_share']*100:.0f}%, "
        f"Transformer v2 {long_conn['transformer_v2']['top10_long_dominated_share']*100:.0f}% (왜곡 작음)"
    )
    fig.text(
        0.5,
        0.032,
        lc_summary,
        ha="center",
        va="center",
        fontsize=9.4,
        color="#334155",
        bbox={"boxstyle": "round,pad=0.45", "facecolor": "#f8fafc", "edgecolor": "#cbd5e1", "linewidth": 0.9},
    )

    fig.subplots_adjust(left=0.14, right=0.98, top=0.73, bottom=0.19, wspace=0.22)
    fig.savefig(out_path, dpi=220, bbox_inches="tight", pad_inches=0.22)
    plt.close(fig)
    return nat_rows, tie_records


def draw_bar_recall_panel(ax, items, title, denom):
    """모델별 Recall@10·Recall@50을 표준 seaborn 수평 그룹 막대와 95% 부트스트랩 신뢰구간으로 그린다."""
    rows = []
    for label, m10, m50 in items:
        rows.append({"모델": label, "지표": "Recall@10", "Recall(%)": m10["recall"] * 100})
        rows.append({"모델": label, "지표": "Recall@50", "Recall(%)": m50["recall"] * 100})
    df = pd.DataFrame(rows)

    sns.barplot(data=df, y="모델", x="Recall(%)", hue="지표", orient="h", ax=ax, edgecolor="white", linewidth=0.6)

    for container, col_idx in [(ax.containers[0], 1), (ax.containers[1], 2)]:
        for bar, item in zip(container, items):
            m = item[col_idx]
            val = m["recall"] * 100
            lo = max(0.0, (m["recall"] - m["low"]) * 100)
            hi = max(0.0, (m["high"] - m["recall"]) * 100)
            cy = bar.get_y() + bar.get_height() / 2
            ax.errorbar([val], [cy], xerr=np.array([[lo], [hi]]),
                        fmt="none", ecolor="#1e293b", elinewidth=1.4, capsize=3, zorder=4)
            x_txt = max(val, m["high"] * 100) + 2.2
            ax.text(x_txt, cy, f"{val:.0f}% ({m['matched']}/{denom})",
                    va="center", ha="left", fontsize=8.3, color="#334155")

    for tick, (label, _, _) in zip(ax.get_yticklabels(), items):
        if "제외" in label:
            tick.set_color("#b91c1c")
            tick.set_fontweight(eda_plots.BOLD_WEIGHT)
        elif "보조" in label:
            tick.set_color("#64748b")
            tick.set_fontweight(eda_plots.BOLD_WEIGHT)
        elif "최종" in label:
            tick.set_color("#047857")
            tick.set_fontweight(eda_plots.BOLD_WEIGHT)

    ax.axvline(100, color="#cbd5e1", linestyle="--", linewidth=0.9, zorder=1)
    ax.set_xlim(0, 132)
    ax.set_xticks([0, 25, 50, 75, 100])
    ax.set_ylabel("")
    ax.set_xlabel(f"Recall (%) — 전체 {denom}건")
    ax.set_title(title, loc="left", pad=14)
    sns.despine(ax=ax)


def plot_model_recall_comparison(summary, syn1, syn2, tgn_metrics, tgn_shift_metrics, fusion_metrics, out_path):
    """차트 5: CIC(16건) vs 합성 APT(20건) 모델별 Recall@10·@50과 95% 신뢰구간 비교를 그린다."""
    cic_items = [
        ("꼬리 희귀도 v1", entry_from_summary(summary["tail_rarity"], 10), entry_from_summary(summary["tail_rarity"], 50)),
        ("꼬리 희귀도 v2", entry_from_summary(summary["tail_rarity_v2"], 10), entry_from_summary(summary["tail_rarity_v2"], 50)),
        ("Isolation Forest v1", entry_from_summary(summary["iforest"], 10), entry_from_summary(summary["iforest"], 50)),
        ("IF v2 [제외]", entry_from_summary(summary["iforest_v2"], 10), entry_from_summary(summary["iforest_v2"], 50)),
        ("Transformer v1", entry_from_summary(summary["transformer"], 10), entry_from_summary(summary["transformer"], 50)),
        ("Transformer v2", entry_from_summary(summary["transformer_v2"], 10), entry_from_summary(summary["transformer_v2"], 50)),
        ("TGN recon", entry_from_metrics(tgn_metrics["pooled"], 10), entry_from_metrics(tgn_metrics["pooled"], 50)),
        ("TGN shift [보조]", entry_from_metrics(tgn_shift_metrics["pooled"], 10), entry_from_metrics(tgn_shift_metrics["pooled"], 50)),
        ("결합 v1 (최종)", entry_from_metrics(fusion_metrics["cic_pooled"]["fusion"], 10), entry_from_metrics(fusion_metrics["cic_pooled"]["fusion"], 50)),
    ]
    syn_items = [
        ("꼬리 희귀도 v1", entry_from_metrics(syn1["models"]["tail_rarity"]["summary"]["main"], 10), entry_from_metrics(syn1["models"]["tail_rarity"]["summary"]["main"], 50)),
        ("꼬리 희귀도 v2", entry_from_metrics(syn1["models"]["tail_rarity_v2"]["summary"]["main"], 10), entry_from_metrics(syn1["models"]["tail_rarity_v2"]["summary"]["main"], 50)),
        ("Isolation Forest v1", entry_from_metrics(syn1["models"]["iforest"]["summary"]["main"], 10), entry_from_metrics(syn1["models"]["iforest"]["summary"]["main"], 50)),
        ("IF v2 [제외]", entry_from_metrics(syn1["models"]["iforest_v2"]["summary"]["main"], 10), entry_from_metrics(syn1["models"]["iforest_v2"]["summary"]["main"], 50)),
        ("Transformer v1", entry_from_metrics(syn1["models"]["transformer"]["summary"]["main"], 10), entry_from_metrics(syn1["models"]["transformer"]["summary"]["main"], 50)),
        ("Transformer v2", entry_from_metrics(syn1["models"]["transformer_v2"]["summary"]["main"], 10), entry_from_metrics(syn1["models"]["transformer_v2"]["summary"]["main"], 50)),
        ("TGN recon", entry_from_metrics(syn2["models"]["tgn_recon"]["summary"]["main"], 10), entry_from_metrics(syn2["models"]["tgn_recon"]["summary"]["main"], 50)),
        ("TGN shift [보조]", entry_from_metrics(syn2["models"]["tgn_shift"]["summary"]["main"], 10), entry_from_metrics(syn2["models"]["tgn_shift"]["summary"]["main"], 50)),
        ("결합 v1 (최종)", entry_from_metrics(fusion_metrics["synthetic_pooled"]["main"], 10), entry_from_metrics(fusion_metrics["synthetic_pooled"]["main"], 50)),
    ]

    fig, (ax_cic, ax_syn) = plt.subplots(1, 2, figsize=(16.2, 7.9), sharey=True)
    draw_bar_recall_panel(ax_cic, cic_items, "CIC 회고 평가 (16건)", 16)
    draw_bar_recall_panel(ax_syn, syn_items, "합성 APT 주 큐 평가 (20건)", 20)
    ax_syn.tick_params(axis="y", labelleft=False)

    handles, labels = ax_cic.get_legend_handles_labels()
    if ax_cic.get_legend() is not None:
        ax_cic.get_legend().remove()
    if ax_syn.get_legend() is not None:
        ax_syn.get_legend().remove()

    fig.suptitle(
        "IF v2는 @10·합성 평가에서 약하고, 결합 v1은 @10은 최고 단독보다 낮지만 @50은 두 평가 모두 가장 높음(구간은 겹침)",
        y=0.965,
        fontweight=eda_plots.BOLD_WEIGHT,
    )
    fig.legend(
        handles,
        [f"{lbl} (막대: 점추정, 선: 95% 신뢰구간)" for lbl in labels],
        loc="upper center",
        bbox_to_anchor=(0.5, 0.908),
        ncol=2,
        frameon=False,
        fontsize=10.0,
    )

    fig.subplots_adjust(left=0.14, right=0.98, top=0.79, bottom=0.11, wspace=0.10)
    fig.savefig(out_path, dpi=220, bbox_inches="tight", pad_inches=0.22)
    plt.close(fig)
    return cic_items, syn_items


def plot_synthetic_pattern_heatmap(syn1, syn2, fusion_metrics, out_path):
    """차트 6: 합성 APT 5종 패턴별 히트맵. 색은 4일 중 50위 안에 든 날 수, 글자는 10위 안 날 수와 날별 최고 순위."""
    hm_models = [
        ("IF v2\n(결합 제외)", lambda p, d: syn1["models"]["iforest_v2"]["days"][d]["main"]["best_rank"][f"{d}-{p}"]),
        ("꼬리 희귀도 v2", lambda p, d: syn1["models"]["tail_rarity_v2"]["days"][d]["main"]["best_rank"][f"{d}-{p}"]),
        ("Transformer v2", lambda p, d: syn1["models"]["transformer_v2"]["days"][d]["main"]["best_rank"][f"{d}-{p}"]),
        ("TGN recon", lambda p, d: syn2["models"]["tgn_recon"]["days"][d]["main"]["best_rank"][f"{d}-{p}"]),
        ("결합 v1\n(최종 선정)", lambda p, d: fusion_metrics["synthetic_patterns"][p][d]["best_rank"]),
    ]

    # 색은 "4일 중 50위 안에 든 날 수"(0~4일)만으로 정한다. 하루만 잘 나온 칸이 진해 보이지 않게 한다.
    tier_colors = ["#f1f5f9", "#dbeafe", "#93c5fd", "#3b82f6", "#1e3a8a"]
    tier_text_colors = {0: "#64748b", 1: "#1e3a8a", 2: "#1e3a8a", 3: "#ffffff", 4: "#ffffff"}

    nrows, ncols = len(PATTERNS), len(hm_models)
    tier_matrix = np.zeros((nrows, ncols), dtype=int)
    cell_texts = [["" for _ in range(ncols)] for _ in range(nrows)]
    pattern_records = {}

    for r, (pat, _) in enumerate(PATTERNS):
        pattern_records[pat] = {}
        for c, (m_label, getter) in enumerate(hm_models):
            ranks = [getter(pat, d) for d in SYN_DAYS]
            valid = [rk for rk in ranks if rk is not None]
            hit10 = sum(1 for rk in valid if rk <= 10)
            hit50 = sum(1 for rk in valid if rk <= 50)
            tier = hit50
            line1 = f"@50 {hit50}/4일 · @10 {hit10}/4일"

            line2 = " / ".join("—" if rk is None else str(rk) for rk in ranks)
            tier_matrix[r, c] = tier
            cell_texts[r][c] = f"{line1}\n{line2}"
            pattern_records[pat][m_label.replace("\n", " ")] = ranks

    fig, ax = plt.subplots(figsize=(12.8, 7.0))
    sns.heatmap(
        tier_matrix,
        annot=False,
        cmap=ListedColormap(tier_colors),
        vmin=-0.5,
        vmax=4.5,
        cbar=False,
        linewidths=4.0,
        linecolor="white",
        ax=ax,
    )

    for r in range(nrows):
        for c in range(ncols):
            tier = int(tier_matrix[r, c])
            ax.text(
                c + 0.5,
                r + 0.5,
                cell_texts[r][c],
                ha="center",
                va="center",
                color=tier_text_colors[tier],
                fontsize=9.8,
                fontweight=eda_plots.BOLD_WEIGHT,
                linespacing=1.45,
            )

    ax.set_xticks(np.arange(ncols) + 0.5, [m[0] for m in hm_models])
    ax.set_yticks(np.arange(nrows) + 0.5, [p[1] for p in PATTERNS])
    ax.tick_params(length=0, pad=8, labelsize=10.2)
    plt.setp(ax.get_yticklabels(), rotation=0)

    for tick, (m_label, _) in zip(ax.get_xticklabels(), hm_models):
        if "결합 제외" in m_label:
            tick.set_color("#b91c1c")
            tick.set_fontweight(eda_plots.BOLD_WEIGHT)
        elif "최종 선정" in m_label:
            tick.set_color("#047857")
            tick.set_fontweight(eda_plots.BOLD_WEIGHT)

    legend_patches = [
        mpatches.Patch(facecolor=tier_colors[n], edgecolor="#94a3b8", label=f"50위 안 {n}일")
        for n in range(4, -1, -1)
    ]
    fig.suptitle(
        "공격 패턴별로 잘 잡는 모델이 다르다",
        y=0.965,
        fontweight=eda_plots.BOLD_WEIGHT,
    )
    fig.text(
        0.5,
        0.905,
        "색: 4일 중 50위 안에 든 날 수  |  셀 아래 줄: 화 / 수 / 목 / 금 최고 순위 (—: 후보 없음)",
        ha="center",
        va="center",
        fontsize=10.1,
        color="#475569",
    )
    fig.legend(handles=legend_patches, loc="upper center", bbox_to_anchor=(0.5, 0.862), ncol=5, frameon=False, fontsize=9.5)

    fig.subplots_adjust(left=0.15, right=0.98, top=0.77, bottom=0.12)
    fig.savefig(out_path, dpi=220, bbox_inches="tight", pad_inches=0.22)
    plt.close(fig)
    return pattern_records


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--eval-dir", type=Path, default=PROJECT_ROOT / "outputs" / "eval")
    parser.add_argument("--diagnostics", type=Path, default=PROJECT_ROOT / "outputs" / "diagnostics")
    parser.add_argument("--out", type=Path, default=PROJECT_ROOT / "outputs" / "eda")
    parser.add_argument("--font", type=Path, default=None, help="직접 지정할 한글 TTF/TTC 글꼴 파일 경로")
    args = parser.parse_args()

    font_name, font_path = setup_style(args.font)
    args.out.mkdir(parents=True, exist_ok=True)

    paths = {
        "summary": args.eval_dir / "_summary" / "summary-20261106T072759Z.json",
        "tail_v2": args.eval_dir / "20261106T072530Z-tail_rarity_v2" / "metrics.json",
        "syn1": args.eval_dir / "20261108T120813Z-synthetic_apt_v1" / "metrics.json",
        "tgn": args.eval_dir / "20261110T104214Z-tgn_recon" / "metrics.json",
        "tgn_shift": args.eval_dir / "20261110T104214Z-tgn_shift" / "metrics.json",
        "tgn_no_nat": args.eval_dir / "20261110T104214Z-tgn_recon" / "no_nat.json",
        "syn2": args.eval_dir / "20261110T104445Z-synthetic_apt_v1" / "metrics.json",
        "fusion": args.eval_dir / "20261111T014619Z-fusion_v1" / "metrics.json",
        "long_conn": args.diagnostics / "long_connections.json",
    }
    data = {k: load_json(p) for k, p in paths.items()}

    c4 = args.out / "04_bias_and_tie_diagnostics.png"
    c5 = args.out / "05_model_recall_comparison.png"
    c6 = args.out / "06_synthetic_pattern_heatmap.png"

    nat_rows, tie_records = plot_bias_and_tie(
        data["summary"], data["tail_v2"], data["tgn"], data["tgn_no_nat"], data["long_conn"], c4
    )
    cic_items, syn_items = plot_model_recall_comparison(
        data["summary"], data["syn1"], data["syn2"], data["tgn"], data["tgn_shift"], data["fusion"], c5
    )
    pattern_records = plot_synthetic_pattern_heatmap(
        data["syn1"], data["syn2"], data["fusion"], c6
    )

    stats = {
        "font": {"name": font_name, "path": font_path},
        "inputs": [file_record(p) for p in paths.values()],
        "nat_bias_comparison": [{"label": lbl, "at_10": m10, "at_50": m50} for lbl, m10, m50 in nat_rows],
        "tail_rarity_v2_tie_sensitivity_at_10": tie_records,
        "long_connections_holdout": {
            m: {
                "holdout_windows": v["holdout_windows"],
                "long_dominated_share_all": v["long_dominated_share_all"],
                "top10_long_dominated_share": v["top10_long_dominated_share"],
                "top20_long_dominated_share": v["top20_long_dominated_share"],
            }
            for m, v in data["long_conn"].items()
        },
        "cic_model_comparison": [{"model": lbl, "at_10": m10, "at_50": m50} for lbl, m10, m50 in cic_items],
        "synthetic_model_comparison": [{"model": lbl, "at_10": m10, "at_50": m50} for lbl, m10, m50 in syn_items],
        "synthetic_pattern_best_ranks": pattern_records,
        "outputs": [file_record(p) for p in [c4, c5, c6]],
    }
    (args.out / "part2_stats.json").write_text(json.dumps(stats, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"wrote part2 charts and stats to {project_path(args.out)} (font={font_name})")


if __name__ == "__main__":
    main()
