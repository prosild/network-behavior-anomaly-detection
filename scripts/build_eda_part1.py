"""1단계 EDA: Silver·Gold v1/v2 데이터 구조·결측·창 분할·특징 변환 근거를 표준 seaborn 한글 차트로 시각화한다.

입력(읽기 전용):
- outputs/silver/conn_v1/conn
- outputs/events/tgn_v1/manifest.json
- outputs/gold/conn_features_v2/{windows, manifest.json}

출력(outputs/eda/):
- 01_silver_protocol_and_missing.png
- 02_window_splits_and_roles.png
- 03_feature_skew_log1p_and_sparsity.png
- part1_stats.json
"""

import argparse
import json
from pathlib import Path
import sys

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import pyarrow.parquet as pq
import seaborn as sns

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
from zeek_ad import eda_plots  # noqa: E402
from zeek_ad.eda_plots import setup_style  # noqa: E402
from zeek_ad.provenance import file_record, project_path  # noqa: E402

DAY_ORDER = ["cic17-mon", "cic17-tue", "cic17-wed", "cic17-thu", "cic17-fri"]
DAY_SHORT = {
    "cic17-mon": "월요일\n(학습/보류)",
    "cic17-tue": "화요일\n(개발)",
    "cic17-wed": "수요일\n(평가)",
    "cic17-thu": "목요일\n(평가)",
    "cic17-fri": "금요일\n(평가)",
}
DAY_ONLY = {"cic17-mon": "월요일", "cic17-tue": "화요일", "cic17-wed": "수요일", "cic17-thu": "목요일", "cic17-fri": "금요일"}


def collect_silver_stats(silver_dir, events_manifest_path):
    """Silver conn Parquet에서 요일별 결측·0바이트 통계를 모으고 이벤트 manifest를 읽는다."""
    cols = ["duration", "orig_bytes", "resp_bytes", "service", "proto", "conn_state"]
    daily_missing = []
    for cap in DAY_ORDER:
        part_dir = silver_dir / "conn" / f"capture_id={cap}"
        table = pq.read_table(part_dir, columns=cols)
        df = table.to_pandas()
        n = len(df)
        dur_na = df["duration"].isna()
        orig_na = df["orig_bytes"].isna()
        resp_na = df["resp_bytes"].isna()
        all_three_na = dur_na & orig_na & resp_na
        daily_missing.append({
            "capture_id": cap,
            "rows": int(n),
            "duration_missing": int(dur_na.sum()),
            "duration_orig_resp_all_missing": int(all_three_na.sum()),
            "orig_bytes_zero": int((df["orig_bytes"] == 0).fillna(False).sum()),
            "resp_bytes_zero": int((df["resp_bytes"] == 0).fillna(False).sum()),
            "service_missing": int(df["service"].isna().sum()),
            "proto_counts": {str(k): int(v) for k, v in df["proto"].value_counts(dropna=False).items()},
        })

    events_manifest = json.loads(events_manifest_path.read_text(encoding="utf-8"))
    proto_logs = {row["capture_id"]: row for row in events_manifest["counts"]}
    return daily_missing, proto_logs


def plot_silver_protocol_and_missing(daily_missing, proto_logs, out_path):
    """차트 1: 요일별 프로토콜 로그 커버리지와 Silver 결측·실측 0바이트를 표준 seaborn 막대 차트로 그린다."""
    proto_rows = []
    day_x_labels_left = {}
    for c in DAY_ORDER:
        row = proto_logs[c]
        ev = float(row["events"])
        day_lbl = f"{DAY_ONLY[c]}\n({ev / 10000:.1f}만건)"
        day_x_labels_left[c] = day_lbl
        auth_file_n = (
            row["ssh_auth_success"] + row["ftp_n"] + row["smb_map_n"]
            + row["krb_n"] + row["dce_n"] + row["ntlm_n"]
        )
        for name, val in [
            ("dns.log", row["dns_n"] / ev * 100),
            ("http.log", row["http_n"] / ev * 100),
            ("ssl.log", row["ssl_version"] / ev * 100),
            ("인증·파일 로그 수 합(ssh·smb 등, 중복 포함)", auth_file_n / ev * 100),
        ]:
            proto_rows.append({"요일": day_lbl, "프로토콜": name, "비율(%)": val})
    df_proto = pd.DataFrame(proto_rows)

    miss_rows = []
    for d in daily_missing:
        c = d["capture_id"]
        n = float(d["rows"])
        day_lbl = DAY_SHORT[c]
        for name, val in [
            ("duration·bytes 동시 결측", d["duration_orig_resp_all_missing"] / n * 100),
            ("orig_bytes == 0 (실측 0)", d["orig_bytes_zero"] / n * 100),
            ("resp_bytes == 0 (실측 0)", d["resp_bytes_zero"] / n * 100),
            ("service 미식별(NULL)", d["service_missing"] / n * 100),
        ]:
            miss_rows.append({"요일": day_lbl, "구분": name, "비율(%)": val})
    df_miss = pd.DataFrame(miss_rows)

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15.6, 6.2))

    sns.barplot(data=df_proto, x="요일", y="비율(%)", hue="프로토콜", ax=ax1, edgecolor="white", linewidth=0.6)
    ax1.set_ylim(0, df_proto["비율(%)"].max() * 1.24)
    ax1.set_xlabel("")
    ax1.set_ylabel("Silver conn 행 대비 비율 (%)")
    ax1.set_title("요일별 프로토콜 로그 커버리지 (Gold v2·TGN 입력)", loc="left", pad=42)
    ax1.legend(title=None, loc="lower left", bbox_to_anchor=(0.0, 1.01), ncol=2, frameon=False, fontsize=9.2)
    sns.despine(ax=ax1)

    sns.barplot(data=df_miss, x="요일", y="비율(%)", hue="구분", ax=ax2, edgecolor="white", linewidth=0.6)
    if ax2.containers:
        ax2.bar_label(ax2.containers[0], fmt="%.1f%%", padding=3, fontsize=8.5, color="#334155")
    ax2.set_ylim(0, df_miss["비율(%)"].max() * 1.24)
    ax2.set_xlabel("")
    ax2.set_ylabel("Silver conn 행 대비 비율 (%)")
    ax2.set_title("Silver 결측(NULL)과 실측 0바이트의 분리", loc="left", pad=42)
    ax2.legend(title=None, loc="lower left", bbox_to_anchor=(0.0, 1.01), ncol=2, frameon=False, fontsize=9.0)
    sns.despine(ax=ax2)

    fig.suptitle("Silver 원시 로그 프로토콜 구성과 결측·실측 0바이트 구분", y=0.96, fontweight=eda_plots.BOLD_WEIGHT)
    fig.subplots_adjust(left=0.06, right=0.98, top=0.74, bottom=0.14, wspace=0.20)
    fig.savefig(out_path, dpi=220, bbox_inches="tight", pad_inches=0.22)
    plt.close(fig)


def plot_window_splits_and_roles(gold, out_path):
    """차트 2: 요일·분할별 5분 창 수와 자산별 originator/responder 창 수를 seaborn 스타일로 그린다."""
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15.6, 7.2))

    split_order = ["train", "holdout", "split_boundary", "capture_edge", "development", "retrospective_eval"]
    split_labels = {
        "train": "학습(train)",
        "holdout": "보류(holdout)",
        "split_boundary": "분할 경계 제외",
        "capture_edge": "캡처 양끝 제외",
        "development": "개발(화요일)",
        "retrospective_eval": "회고 평가(수~금)",
    }
    counts = gold.groupby(["capture_id", "split"]).size().unstack(fill_value=0)
    active_splits = [sp for sp in split_order if sp in counts.columns and counts[sp].sum() > 0]
    plot_df = counts.reindex(DAY_ORDER)[active_splits].rename(columns=split_labels)
    plot_df.index = [DAY_ONLY[c] for c in DAY_ORDER]

    palette = sns.color_palette("deep", len(active_splits))
    plot_df.plot(kind="bar", stacked=True, width=0.58, color=palette, edgecolor="white", linewidth=0.7, ax=ax1)
    ax1.tick_params(axis="x", rotation=0)

    cum_bottom = np.zeros(len(DAY_ORDER))
    for col in plot_df.columns:
        vals = plot_df[col].to_numpy(dtype=float)
        for i, v in enumerate(vals):
            if v >= 150:
                ax1.text(i, cum_bottom[i] + v / 2, f"{int(v):,}", ha="center", va="center",
                         color="white", fontsize=8.8, fontweight=eda_plots.BOLD_WEIGHT)
        cum_bottom += vals

    role_by_day = gold.groupby(["capture_id", "role"]).size().unstack(fill_value=0)
    for i, c in enumerate(DAY_ORDER):
        orig_n = int(role_by_day.loc[c, "originator"])
        resp_n = int(role_by_day.loc[c, "responder"])
        ax1.text(i, cum_bottom[i] + 35, f"출발 {orig_n:,}\n수신 {resp_n:,}",
                 ha="center", va="bottom", fontsize=8.3, color="#334155")

    ax1.set_ylim(0, cum_bottom.max() * 1.24)
    ax1.set_xlabel("")
    ax1.set_ylabel("5분 창 개수")
    ax1.set_title("요일·시간 분할별 Gold 5분 창 수", loc="left", pad=44)
    ax1.legend(title=None, loc="lower left", bbox_to_anchor=(-0.02, 1.01), ncol=3, frameon=False, fontsize=8.8)
    sns.despine(ax=ax1)

    # 오른쪽: 14개 점수화 대상 자산별 originator vs responder 창 수 (표준 seaborn 수평 막대)
    asset_role = gold.groupby(["asset_id", "role"]).size().unstack(fill_value=0)
    asset_role["total"] = asset_role.sum(axis=1)
    asset_role = asset_role.sort_values("total", ascending=False)

    role_rows = []
    for ip, row in asset_role.iterrows():
        short_ip = ip.replace("192.168.10.", ".")
        role_rows.append({"자산 IP": short_ip, "역할": "출발(originator)", "5분 창 수": int(row["originator"])})
        role_rows.append({"자산 IP": short_ip, "역할": "수신(responder)", "5분 창 수": int(row["responder"])})
    df_role = pd.DataFrame(role_rows)

    sns.barplot(data=df_role, y="자산 IP", x="5분 창 수", hue="역할", orient="h", ax=ax2, edgecolor="white", linewidth=0.5)
    for container in ax2.containers:
        ax2.bar_label(container, fmt="{:,.0f}", padding=3, fontsize=7.8, color="#334155")
    ax2.set_xlim(0, df_role["5분 창 수"].max() * 1.18)
    ax2.set_xlabel("5일 합계 5분 창 개수")
    ax2.set_ylabel("내부 자산 IP (192.168.10.x)")
    ax2.set_title(f"점수화 대상 {len(asset_role)}개 자산별 역할 분포", loc="left", pad=44)
    ax2.legend(title=None, loc="lower left", bbox_to_anchor=(0.0, 1.01), ncol=2, frameon=False, fontsize=9.2)
    sns.despine(ax=ax2)

    fig.suptitle(f"Gold v2 5분 창 분할 구조(총 {len(gold):,}창)와 자산별 역할 분포", y=0.96, fontweight=eda_plots.BOLD_WEIGHT)
    fig.subplots_adjust(left=0.06, right=0.98, top=0.75, bottom=0.12, wspace=0.24)
    fig.savefig(out_path, dpi=220, bbox_inches="tight", pad_inches=0.22)
    plt.close(fig)
    return asset_role.sort_values("total", ascending=True)


def skewness(arr):
    """표본 왜도(3차 표준화 적률)를 계산한다."""
    x = np.asarray(arr, dtype=float)
    x = x[np.isfinite(x)]
    s = x.std(ddof=0)
    if len(x) == 0 or s == 0:
        return 0.0
    return float(np.mean(((x - x.mean()) / s) ** 3))


def plot_skew_log1p_and_sparsity(gold, gold_manifest, out_path):
    """차트 3: 월요일 train의 log1p 전후 히스토그램(sns.histplot)과 Gold v2 24개 특징 희소성(sns.barplot)을 그린다."""
    train = gold[gold["split"] == "train"]
    demo_features = ["conn_count", "out_bytes_sum", "duration_p95"]
    palette_deep = sns.color_palette("deep")

    fig = plt.figure(figsize=(16.4, 7.6))
    gs = fig.add_gridspec(3, 3, width_ratios=[1.0, 1.0, 1.48], left=0.06, right=0.98, top=0.84, bottom=0.09, wspace=0.34, hspace=0.55)

    skew_records = {}
    for row_idx, col in enumerate(demo_features):
        vals = train[col].dropna().to_numpy(dtype=float)
        log_vals = np.log1p(np.clip(vals, a_min=0, a_max=None))
        skew_raw = skewness(vals)
        skew_log = skewness(log_vals)
        skew_records[col] = {
            "n_nonnull": int(len(vals)),
            "skew_raw": round(skew_raw, 3),
            "skew_log1p": round(skew_log, 3),
            "p50_raw": round(float(np.median(vals)), 3),
            "p99_raw": round(float(np.percentile(vals, 99)), 3),
            "max_raw": round(float(vals.max()), 3),
        }

        ax_raw = fig.add_subplot(gs[row_idx, 0])
        ax_log = fig.add_subplot(gs[row_idx, 1])

        sns.histplot(vals, bins=30, color=palette_deep[3], edgecolor="white", linewidth=0.4, ax=ax_raw)
        ax_raw.set_title(f"{col} 변환 전 (왜도={skew_raw:.2f})", fontsize=10.2)
        ax_raw.set_ylabel("창 수", fontsize=9.5)
        sns.despine(ax=ax_raw)

        sns.histplot(log_vals, bins=30, color=palette_deep[0], edgecolor="white", linewidth=0.4, ax=ax_log)
        ax_log.set_title(f"log1p 후 (왜도={skew_log:.2f})", fontsize=10.2)
        ax_log.set_ylabel("")
        sns.despine(ax=ax_log)

        if row_idx == 2:
            ax_raw.set_xlabel("원본 값", fontsize=9.8)
            ax_log.set_xlabel("log1p(값)", fontsize=9.8)

    ax_sp = fig.add_subplot(gs[:, 2])
    total_win = gold_manifest["windows"]
    nonzero = gold_manifest["nonzero_windows"]
    items = sorted(nonzero.items(), key=lambda kv: kv[1], reverse=True)
    sp_rows = []
    for k, cnt in items:
        pct = cnt / total_win * 100
        bucket = "5% 미만 (극희소)" if pct < 5 else ("5~30% (중간)" if pct < 30 else "30% 이상 (상시)")
        sp_rows.append({"특징": k, "비영 비율(%)": pct, "창 수": cnt, "희소 구간": bucket})
    df_sp = pd.DataFrame(sp_rows)

    bucket_palette = {
        "5% 미만 (극희소)": palette_deep[3],
        "5~30% (중간)": palette_deep[1],
        "30% 이상 (상시)": palette_deep[0],
    }
    sns.barplot(data=df_sp, y="특징", x="비영 비율(%)", hue="희소 구간", dodge=False,
                palette=bucket_palette, orient="h", ax=ax_sp, edgecolor="white", linewidth=0.5)
    for i, row in df_sp.iterrows():
        ax_sp.text(row["비영 비율(%)"] + 1.2, i, f"{row['비영 비율(%)']:.1f}% ({row['창 수']:,})",
                   va="center", fontsize=8.3, color="#334155")

    ax_sp.set_xlim(0, 124)
    ax_sp.set_ylabel("")
    ax_sp.set_xlabel(f"전체 {total_win:,}창 중 0보다 큰 창 비율 (%)")
    ax_sp.set_title("Gold v2 프로토콜 로그 24개 특징 희소성", loc="left", pad=28)
    ax_sp.legend(title=None, loc="lower left", bbox_to_anchor=(0.0, 1.005), ncol=3, frameon=False, fontsize=8.8)
    sns.despine(ax=ax_sp)

    # 제목의 개수는 직접 적지 않고 manifest의 비영 창 수에서 센다.
    sparse_n = int((df_sp["비영 비율(%)"] < 30).sum())
    fig.suptitle(f"꼬리가 긴 분포는 log1p로 완화하고, 프로토콜 로그 특징 {len(df_sp)}개 중 {sparse_n}개는 0이 아닌 창이 30% 미만",
                 y=0.955, fontweight=eda_plots.BOLD_WEIGHT)
    fig.savefig(out_path, dpi=220, bbox_inches="tight", pad_inches=0.22)
    plt.close(fig)
    return skew_records


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--silver", type=Path, default=PROJECT_ROOT / "outputs" / "silver" / "conn_v1")
    parser.add_argument("--events-manifest", type=Path, default=PROJECT_ROOT / "outputs" / "events" / "tgn_v1" / "manifest.json")
    parser.add_argument("--gold-v2", type=Path, default=PROJECT_ROOT / "outputs" / "gold" / "conn_features_v2")
    parser.add_argument("--out", type=Path, default=PROJECT_ROOT / "outputs" / "eda")
    parser.add_argument("--font", type=Path, default=None, help="직접 지정할 한글 TTF/TTC 글꼴 파일 경로")
    args = parser.parse_args()

    font_name, font_path = setup_style(args.font)
    args.out.mkdir(parents=True, exist_ok=True)

    daily_missing, proto_logs = collect_silver_stats(args.silver, args.events_manifest)
    gold = pd.read_parquet(args.gold_v2 / "windows")
    gold["capture_id"] = gold["capture_id"].astype(str)
    gold_manifest = json.loads((args.gold_v2 / "manifest.json").read_text(encoding="utf-8"))

    c1 = args.out / "01_silver_protocol_and_missing.png"
    c2 = args.out / "02_window_splits_and_roles.png"
    c3 = args.out / "03_feature_skew_log1p_and_sparsity.png"

    plot_silver_protocol_and_missing(daily_missing, proto_logs, c1)
    asset_role = plot_window_splits_and_roles(gold, c2)
    skew_records = plot_skew_log1p_and_sparsity(gold, gold_manifest, c3)

    split_summary = (
        gold.groupby(["capture_id", "split", "role"]).size().reset_index(name="windows")
        .sort_values(["capture_id", "split", "role"]).to_dict(orient="records")
    )
    stats = {
        "font": {"name": font_name, "path": font_path},
        "inputs": [
            file_record(args.events_manifest),
            file_record(args.gold_v2 / "manifest.json"),
        ],
        "silver_daily_missing_and_zeros": daily_missing,
        "protocol_log_counts": [proto_logs[c] for c in DAY_ORDER],
        "gold_v2_total_windows": int(len(gold)),
        "gold_v2_split_role_summary": split_summary,
        "scored_asset_role_counts": {
            ip: {"originator": int(r["originator"]), "responder": int(r["responder"]), "total": int(r["total"])}
            for ip, r in asset_role.iterrows()
        },
        "monday_train_skew_log1p": skew_records,
        "gold_v2_nonzero_windows": gold_manifest["nonzero_windows"],
        "outputs": [file_record(p) for p in [c1, c2, c3]],
    }
    stats_path = args.out / "part1_stats.json"
    stats_path.write_text(json.dumps(stats, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"wrote part1 charts and stats to {project_path(args.out)} (font={font_name})")


if __name__ == "__main__":
    main()
