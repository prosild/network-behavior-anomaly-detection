"""EDA 차트의 한글 글꼴 탐색·등록과 공통 seaborn·matplotlib 스타일을 제공한다."""

from pathlib import Path
import struct
import sys

import matplotlib

matplotlib.use("Agg")
from matplotlib import font_manager as fm
from matplotlib.ft2font import FT2Font
import matplotlib.pyplot as plt
import seaborn as sns

# 리눅스 네이티브 한글 글꼴을 우선 찾고, 없을 때만 WSL Windows 글꼴을 쓴다.
KOREAN_FONT_PAIRS = [
    ("/usr/share/fonts/truetype/nanum/NanumBarunGothic.ttf", "/usr/share/fonts/truetype/nanum/NanumBarunGothicBold.ttf"),
    ("/usr/share/fonts/truetype/nanum/NanumGothic.ttf", "/usr/share/fonts/truetype/nanum/NanumGothicBold.ttf"),
    ("/usr/share/fonts/truetype/nanum/NanumSquareR.ttf", "/usr/share/fonts/truetype/nanum/NanumSquareB.ttf"),
    ("/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc", "/usr/share/fonts/opentype/noto/NotoSansCJK-Bold.ttc"),
    ("/usr/share/fonts/truetype/noto/NotoSansKR-Regular.ttf", "/usr/share/fonts/truetype/noto/NotoSansKR-Bold.ttf"),
    ("/mnt/c/Windows/Fonts/malgun.ttf", "/mnt/c/Windows/Fonts/malgunbd.ttf"),
    ("/mnt/c/Windows/Fonts/gulim.ttc", None),
]
KOREAN_FONT_NAMES = [
    "NanumBarunGothic",
    "NanumGothic",
    "NanumSquare",
    "Noto Sans CJK KR",
    "Noto Sans KR",
    "Malgun Gothic",
    "AppleGothic",
    "UnDotum",
]


def supports_korean(font_path):
    """글꼴 파일이 실제 한글 음절('한', '글')을 포함하는지 확인한다."""
    try:
        cmap = FT2Font(str(font_path)).get_charmap()
        return ord("한") in cmap and ord("글") in cmap
    except Exception:
        return False


BOLD_WEIGHT = "bold"


def _ttf_weight(font_path):
    """TTF 파일의 OS/2 테이블에서 실제 글꼴 굵기(usWeightClass)를 읽는다."""
    try:
        data = Path(font_path).read_bytes()
        num_tables = struct.unpack(">H", data[4:6])[0]
        for i in range(num_tables):
            offset = 12 + i * 16
            tag, _, tbl_off, _ = struct.unpack(">4sIII", data[offset : offset + 16])
            if tag == b"OS/2" and tbl_off + 6 <= len(data):
                return struct.unpack(">H", data[tbl_off + 4 : tbl_off + 6])[0]
    except Exception:
        pass
    return "bold"


def _register_pair(reg_path, bold_path=None):
    global BOLD_WEIGHT
    fm.fontManager.addfont(str(reg_path))
    if bold_path and Path(bold_path).is_file():
        fm.fontManager.addfont(str(bold_path))
        BOLD_WEIGHT = _ttf_weight(bold_path)
    else:
        BOLD_WEIGHT = "bold"
    return fm.FontProperties(fname=str(reg_path)).get_name(), str(reg_path)


def configure_korean_font(user_font_path=None):
    """한글 렌더링이 가능한 글꼴(가능하면 굵은 글꼴 포함)을 찾아 matplotlib에 등록한다."""
    if user_font_path is not None:
        p = Path(user_font_path)
        if not p.is_file() or not supports_korean(p):
            sys.exit(f"지정한 글꼴을 쓸 수 없다(한글 미지원 또는 파일 없음): {p}")
        return _register_pair(p)

    for reg, bold in KOREAN_FONT_PAIRS:
        p = Path(reg)
        if p.is_file() and supports_korean(p):
            return _register_pair(p, bold)

    for root in [Path("/usr/share/fonts"), Path.home() / ".local" / "share" / "fonts"]:
        if not root.is_dir():
            continue
        for p in sorted(root.rglob("*.ttf")) + sorted(root.rglob("*.ttc")):
            if any(k in p.name.lower() for k in ("nanum", "noto", "pretendard", "spoqa")) and supports_korean(p):
                return _register_pair(p)

    installed = {f.name: f.fname for f in fm.fontManager.ttflist}
    for name in KOREAN_FONT_NAMES:
        fname = installed.get(name)
        if fname and supports_korean(fname):
            return name, fname

    sys.exit(
        "한글 글꼴을 찾지 못했습니다. 'sudo apt-get install -y fonts-nanum'을 설치하거나 "
        "'--font /path/to/korean.ttf'로 글꼴 파일 경로를 지정하세요."
    )


def setup_style(user_font_path=None):
    """seaborn 테마와 한글 글꼴, 읽기 쉬운 여백·타이포그래피 기본값을 적용한다."""
    font_name, font_path = configure_korean_font(user_font_path)
    # set_theme가 font.family를 덮어쓰므로 먼저 호출한 뒤 rcParams를 다시 고정한다.
    sns.set_theme(style="whitegrid", palette="deep", context="notebook")
    plt.rcParams.update({
        "font.family": font_name,
        "axes.unicode_minus": False,
        "font.size": 10.5,
        "axes.titlesize": 12.2,
        "axes.titleweight": BOLD_WEIGHT,
        "axes.labelsize": 10.5,
        "xtick.labelsize": 9.8,
        "ytick.labelsize": 9.8,
        "legend.fontsize": 9.8,
        "figure.titlesize": 14.5,
        "figure.titleweight": BOLD_WEIGHT,
        "axes.edgecolor": "#cbd5e1",
        "axes.linewidth": 0.9,
        "grid.color": "#e2e8f0",
        "grid.linestyle": "-",
        "grid.linewidth": 0.8,
        "figure.facecolor": "white",
        "axes.facecolor": "white",
    })
    return font_name, font_path
