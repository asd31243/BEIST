"""Render the English and Chinese BEIST protocol figures as SVG-first assets."""
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib import font_manager
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch


ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "figures"
OUT.mkdir(parents=True, exist_ok=True)


def configure_cjk_font() -> None:
    for candidate in [Path(r"C:\Windows\Fonts\msyh.ttc"), Path(r"C:\Windows\Fonts\simhei.ttf"), Path(r"C:\Windows\Fonts\NotoSansSC-VF.ttf")]:
        if candidate.is_file():
            font_manager.fontManager.addfont(str(candidate))
            family = font_manager.FontProperties(fname=str(candidate)).get_name()
            plt.rcParams.update({"font.family": family, "font.sans-serif": [family, "DejaVu Sans"], "axes.unicode_minus": False})
            return


def draw_protocol(chinese: bool) -> None:
    if chinese:
        title = "BEIST 证据测量协议"
        subtitle = "从已记录沙箱事件到可审计证据的确定性路径"
        boxes = [
            ("原始报告", "16 个 JSON 字段\n保留缺失性"),
            ("行为原子", "规范化事件\n字段溯源"),
            ("能力判定", "S / N / I 状态\n跨字段佐证"),
            ("证据记录", "溯源、冲突\n与脆弱性画像"),
        ]
        stress_title = "压力测试"
        stress_body = "允许删除 · 标识符规范化 · 受控替换\n能力级 MEDC 与 Pareto 最小扰动集合"
        stem = "beist_protocol_zh"
    else:
        title = "BEIST evidence measurement protocol"
        subtitle = "A deterministic path from recorded sandbox events to auditable evidence"
        boxes = [
            ("Raw report", "16 JSON fields\nmissingness retained"),
            ("Activity atoms", "normalised event\nfield provenance"),
            ("Capabilities", "S / N / I state\ncross-field corroboration"),
            ("Evidence record", "provenance, conflicts\nand fragility profile"),
        ]
        stress_title = "Stress testing"
        stress_body = "admissible deletion · identifier normalisation · controlled substitution\ncapability-level MEDC and Pareto-minimal disruption sets"
        stem = "beist_protocol"

    fig, ax = plt.subplots(figsize=(10.5, 5.3), constrained_layout=True)
    ax.set_xlim(0, 16); ax.set_ylim(0, 9); ax.axis("off")
    ax.text(.55, 8.35, title, fontsize=20, fontweight="bold", color="#17324D", va="top")
    ax.text(.55, 7.75, subtitle, fontsize=10.5, color="#6E7B87", va="top")
    fills = ["#EAF1F6", "#EDF6F4", "#FFF6E9", "#FAEDED"]
    edges = ["#2F6B9A", "#2E8B86", "#C4872F", "#B94A48"]
    xs = [.55, 4.45, 8.35, 12.25]
    for i, ((heading, body), x, fill, edge) in enumerate(zip(boxes, xs, fills, edges)):
        width = 3.15
        box = FancyBboxPatch((x, 4.75), width, 1.95, boxstyle="round,pad=.16,rounding_size=.18",
                             facecolor=fill, edgecolor=edge, linewidth=1.7)
        ax.add_patch(box)
        ax.text(x + .27, 6.15, heading, fontsize=12.5, fontweight="bold", color="#17324D", va="top")
        ax.text(x + .27, 5.55, body, fontsize=9.5, color="#24313D", va="top", linespacing=1.45)
        if i < len(boxes) - 1:
            ax.add_patch(FancyArrowPatch((x + width + .08, 5.72), (xs[i + 1] - .08, 5.72),
                                         arrowstyle="-|>", mutation_scale=13, linewidth=1.6, color="#17324D"))
    stress = FancyBboxPatch((2.6, 1.25), 10.8, 1.65, boxstyle="round,pad=.16,rounding_size=.18",
                            facecolor="#F8FAFC", edgecolor="#17324D", linewidth=1.5)
    ax.add_patch(stress)
    ax.text(3.0, 2.55, stress_title, fontsize=12, fontweight="bold", color="#17324D", va="top")
    ax.text(3.0, 2.08, stress_body, fontsize=9.5, color="#24313D", va="top", linespacing=1.35)
    ax.add_patch(FancyArrowPatch((9.92, 4.72), (8.0, 2.98), connectionstyle="arc3,rad=.18",
                                 arrowstyle="-|>", mutation_scale=13, linewidth=1.6, color="#C4872F"))
    fig.savefig(OUT / f"{stem}.svg", bbox_inches="tight")
    fig.savefig(OUT / f"{stem}_svg-raw.pdf", format="pdf", bbox_inches="tight")
    fig.savefig(OUT / f"{stem}.png", dpi=220, bbox_inches="tight")
    plt.close(fig)


def main() -> None:
    configure_cjk_font()
    draw_protocol(False)
    draw_protocol(True)


if __name__ == "__main__":
    main()


