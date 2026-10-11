"""Kiểu hình dùng chung cho các notebook của đề tài (chữ Computer Modern, không viền trên và phải, màu đồng nhất)."""
import os
import matplotlib.pyplot as plt

NAVY, OURS, OURS_L, SKY, GOLD, GREY = "#1F3A5F", "#E4572E", "#FBE3DA", "#8FB8DE", "#E9B44C", "#A9B8C6"
FONT, BOLD = "serif", "serif"
PAGE_WIDTH = 4.8          # bề rộng in của một hình trong bài báo (inch)


def setup():
    """Đặt kiểu hình: phông Computer Modern, chữ đen, bỏ viền trên và phải, lưu PDF nhúng phông TrueType."""
    plt.rcParams.update({
        "font.family": "serif", "font.serif": ["cmr10", "DejaVu Serif"], "mathtext.fontset": "cm", "axes.formatter.use_mathtext": True,
        "axes.unicode_minus": False, "text.color": "black", "axes.labelcolor": "black", "xtick.color": "black", "ytick.color": "black",
        "axes.edgecolor": "black", "axes.spines.top": False, "axes.spines.right": False, "axes.linewidth": 0.6,
        "figure.dpi": 110, "savefig.dpi": 300, "pdf.fonttype": 42, "ps.fonttype": 42,
    })


def panel(ax, tag):
    """Ghi nhãn (a), (b)... ở góc trên bên trái của một khung hình."""
    ax.text(0, 1.04, tag, transform=ax.transAxes, ha="left", va="bottom")


def save(fig, name, paper=False):
    """Lưu hình dạng PNG vào Figures/ và (nếu paper=True) dạng PDF vào Paper/figs/."""
    os.makedirs("../Figures", exist_ok=True)
    fig.savefig(f"../Figures/{name}.png", dpi=200)
    if paper:
        os.makedirs("../Paper/figs", exist_ok=True)
        fig.savefig(f"../Paper/figs/{name}.pdf")
    plt.show()
