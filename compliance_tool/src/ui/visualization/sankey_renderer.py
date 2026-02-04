import ctypes
import io
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

import matplotlib
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
from matplotlib.patches import FancyBboxPatch, PathPatch
from matplotlib.path import Path
from PIL import Image

from src.ui.visualization.style_theme import Theme, get_theme
from src.ui.visualization.visual_model import SankeyLink, SankeyNode


matplotlib.use("TkAgg")


@dataclass
class RenderContext:
    nodes: Dict[str, SankeyNode]
    positions: Dict[str, Tuple[float, float, float, float]]


class SankeyRenderer:
    def __init__(self, parent, theme_name: str = "Light"):
        self.theme = get_theme(theme_name)
        self.fig = Figure(figsize=(9.5, 5.2), dpi=110)
        self.ax = self.fig.add_subplot(111)
        self.ax.set_axis_off()
        self.canvas = FigureCanvasTkAgg(self.fig, master=parent)
        self.canvas_widget = self.canvas.get_tk_widget()

        self.context = RenderContext(nodes={}, positions={})
        self.selected_node: Optional[str] = None
        self.hover_node: Optional[str] = None
        self._view_limits: Optional[Tuple[Tuple[float, float], Tuple[float, float]]] = None
        self.canvas.mpl_connect("button_release_event", self._capture_view)
        self.canvas.mpl_connect("scroll_event", self._on_scroll)

    def set_theme(self, theme_name: str) -> None:
        self.theme = get_theme(theme_name)

    def get_widget(self):
        return self.canvas_widget
    
    def get_context(self) -> RenderContext:
        return self.context

    def draw(
        self,
        nodes: List[SankeyNode],
        links: List[SankeyLink],
        headers: List[str],
        preserve_view: bool = False,
    ) -> None:
        self.ax.clear()
        self.ax.set_axis_off()
        self.ax.set_facecolor(self.theme.background)
        self.fig.set_facecolor(self.theme.background)

        self.context.nodes = {n.node_id: n for n in nodes}
        self.context.positions = self._layout(nodes)

        self._draw_headers(headers)
        self._draw_links(links)
        self._draw_nodes()

        if preserve_view and self._view_limits:
            self.ax.set_xlim(*self._view_limits[0])
            self.ax.set_ylim(*self._view_limits[1])
        else:
            self.ax.set_xlim(0.0, 1.0)
            self.ax.set_ylim(0.0, 1.0)
            self._view_limits = (self.ax.get_xlim(), self.ax.get_ylim())

        self.canvas.draw_idle()

    def export(self, path: str, fmt: str, dpi: int = 220) -> None:
        self.fig.savefig(path, format=fmt, dpi=dpi, bbox_inches="tight")

    def copy_to_clipboard(self) -> None:
        buf = io.BytesIO()
        self.fig.savefig(buf, format="png", dpi=200, bbox_inches="tight")
        buf.seek(0)
        img = Image.open(buf)
        self._copy_image_to_clipboard(img)

    def _layout(self, nodes: List[SankeyNode]) -> Dict[str, Tuple[float, float, float, float]]:
        layer_map = {"system": 0, "testcase": 1, "teststep": 1}
        layers: Dict[int, List[str]] = {}
        for node in nodes:
            layer = layer_map.get(node.node_type, 0)
            layers.setdefault(layer, []).append(node.node_id)
        for layer in layers:
            layers[layer].sort()

        positions: Dict[str, Tuple[float, float, float, float]] = {}
        width = 1.0
        height = 1.0
        margin_x = 0.08
        margin_y = 0.12
        max_layer = max(layers.keys()) if layers else 0

        for layer_idx, node_ids in layers.items():
            x = margin_x + (width - 2 * margin_x) * (layer_idx / max(1, max_layer))
            count = len(node_ids)
            if count == 0:
                continue
            gap = (height - 2 * margin_y) / max(1, count)
            node_h = min(0.09, gap * 0.85)
            for i, node_id in enumerate(node_ids):
                y = height - margin_y - (i + 1) * gap + (gap - node_h) / 2
                positions[node_id] = (x, y, 0.24, node_h)
        return positions

    def _draw_headers(self, headers: List[str]) -> None:
        if not headers:
            return
        span = 1.0 / max(1, len(headers) - 1)
        for idx, text in enumerate(headers):
            x = 0.08 + (0.84 * (idx / max(1, len(headers) - 1)))
            self.ax.text(
                x,
                0.98,
                text,
                ha="center",
                va="top",
                fontsize=11,
                fontweight="bold",
                color=self.theme.text,
            )

    def _draw_nodes(self) -> None:
        for node_id, (x, y, w, h) in self.context.positions.items():
            node = self.context.nodes[node_id]
            fill, edge = self._node_colors(node.node_type)
            highlight = self.selected_node or self.hover_node
            alpha = 1.0 if not highlight or highlight == node_id else 0.25

            shadow = FancyBboxPatch(
                (x + 0.006, y - 0.006),
                w,
                h,
                boxstyle="round,pad=0.01,rounding_size=0.02",
                linewidth=0,
                facecolor=self.theme.shadow,
                alpha=0.12,
                zorder=1,
            )
            self.ax.add_patch(shadow)

            rect = FancyBboxPatch(
                (x, y),
                w,
                h,
                boxstyle="round,pad=0.01,rounding_size=0.02",
                linewidth=1.0,
                edgecolor=edge,
                facecolor=fill,
                alpha=alpha,
                zorder=2,
            )
            self.ax.add_patch(rect)

            sheen = FancyBboxPatch(
                (x + 0.002, y + h * 0.6),
                w - 0.004,
                h * 0.35,
                boxstyle="round,pad=0.01,rounding_size=0.02",
                linewidth=0,
                facecolor="#ffffff",
                alpha=0.18 if self.theme.name == "Light" else 0.08,
                zorder=2,
            )
            self.ax.add_patch(sheen)

            label = node.label
            if node.node_type == "system":
                label = f"R {label}"
            elif node.node_type == "testcase":
                label = f"TC {label}"
            elif node.node_type == "teststep":
                label = f"TS {label}"
            self.ax.text(
                x + w / 2,
                y + h / 2,
                label,
                ha="center",
                va="center",
                fontsize=10.5,
                fontweight="bold",
                family="monospace",
                color=self.theme.text,
                zorder=3,
            )

    def _draw_links(self, links: List[SankeyLink]) -> None:
        for link in links:
            if link.source not in self.context.positions or link.target not in self.context.positions:
                continue
            highlight = self.selected_node or self.hover_node
            if highlight and highlight not in (link.source, link.target):
                alpha = 0.1
            else:
                alpha = 0.7

            sx, sy, sw, sh = self.context.positions[link.source]
            tx, ty, tw, th = self.context.positions[link.target]
            x0 = sx + sw
            y0 = sy + sh / 2
            x1 = tx
            y1 = ty + th / 2
            ctrl = (x1 - x0) * 0.5
            verts = [
                (x0, y0),
                (x0 + ctrl, y0),
                (x1 - ctrl, y1),
                (x1, y1),
            ]
            codes = [Path.MOVETO, Path.CURVE4, Path.CURVE4, Path.CURVE4]
            path = Path(verts, codes)
            width = 1.2 + min(6, link.value)
            patch = PathPatch(
                path,
                facecolor="none",
                edgecolor=link.color,
                linewidth=width,
                alpha=alpha,
                zorder=0,
            )
            self.ax.add_patch(patch)

    def _node_colors(self, node_type: str) -> Tuple[str, str]:
        if node_type == "system":
            return self.theme.system_node, self.theme.system_node_edge
        if node_type == "testcase":
            return self.theme.testcase_node, self.theme.testcase_node
        if node_type == "teststep":
            return self.theme.teststep_node, self.theme.teststep_node
        return "#cccccc", "#999999"

    def _copy_image_to_clipboard(self, image: Image.Image) -> None:
        output = io.BytesIO()
        image = image.convert("RGB")
        image.save(output, "BMP")
        data = output.getvalue()[14:]
        output.close()

        cf_dib = 8
        user32 = ctypes.windll.user32
        kernel32 = ctypes.windll.kernel32

        user32.OpenClipboard(0)
        user32.EmptyClipboard()
        h_global = kernel32.GlobalAlloc(0x2000, len(data))
        ptr = kernel32.GlobalLock(h_global)
        ctypes.memmove(ptr, data, len(data))
        kernel32.GlobalUnlock(h_global)
        user32.SetClipboardData(cf_dib, h_global)
        user32.CloseClipboard()

    def _capture_view(self, _event=None) -> None:
        if self.ax is None:
            return
        self._view_limits = (self.ax.get_xlim(), self.ax.get_ylim())

    def _on_scroll(self, event) -> None:
        if event.inaxes != self.ax:
            return
        if event.xdata is None or event.ydata is None:
            return
        base_scale = 1.15
        scale = base_scale ** (-event.step)
        xlim = self.ax.get_xlim()
        ylim = self.ax.get_ylim()
        x_center = event.xdata
        y_center = event.ydata
        new_width = (xlim[1] - xlim[0]) * scale
        new_height = (ylim[1] - ylim[0]) * scale
        self.ax.set_xlim(x_center - new_width / 2, x_center + new_width / 2)
        self.ax.set_ylim(y_center - new_height / 2, y_center + new_height / 2)
        self._capture_view()
        self.canvas.draw_idle()
