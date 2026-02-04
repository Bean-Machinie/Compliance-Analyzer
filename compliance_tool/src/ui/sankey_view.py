from typing import Dict, List, Optional, Tuple

import tkinter as tk
from tkinter import ttk
from matplotlib.backends.backend_tkagg import NavigationToolbar2Tk

from src.backend.models import AnalysisResult, Requirement, TestCase
from src.ui.filters_panel import FiltersPanel
from src.ui.visualization.interaction_controller import build_view1_data, build_view2_data, test_case_id
from src.ui.visualization.sankey_renderer import SankeyRenderer
from src.ui.visualization.style_theme import get_theme
from src.ui.visualization.visual_model import resolve_link_color


class SankeyView(ttk.Frame):
    def __init__(self, parent: tk.Widget):
        super().__init__(parent)
        self.requirements: Dict[str, Requirement] = {}
        self.results_map: Dict[str, AnalysisResult] = {}
        self.test_cases: List[TestCase] = []
        self.selected_node: Optional[str] = None
        self._last_nodes: List = []
        self._last_links: List = []
        self._last_headers: List[str] = []

        self.banner_var = tk.StringVar(value="TRACEABILITY VIEW")
        self.banner_label = ttk.Label(self, textvariable=self.banner_var, anchor="center", padding=6)
        self.banner_label.pack(fill="x", padx=6, pady=4)

        self.filters_panel = FiltersPanel(self, self._on_filters_changed)
        self.filters_panel.pack(fill="x", padx=6, pady=4)

        control_row = ttk.Frame(self)
        control_row.pack(fill="x", padx=6)
        ttk.Button(control_row, text="Clear Highlight", command=self.clear_selection).pack(side="left", padx=4)
        ttk.Button(control_row, text="Export PNG", command=lambda: self.export_image("png")).pack(side="left", padx=4)
        ttk.Button(control_row, text="Export SVG", command=lambda: self.export_image("svg")).pack(side="left", padx=4)
        ttk.Button(control_row, text="Copy to Clipboard", command=self.copy_to_clipboard).pack(side="left", padx=4)

        main = ttk.Frame(self)
        main.pack(fill="both", expand=True)

        canvas_frame = ttk.Frame(main)
        canvas_frame.pack(fill="both", expand=True, padx=6, pady=6)

        self.renderer = SankeyRenderer(canvas_frame)
        canvas_widget = self.renderer.get_widget()
        canvas_widget.pack(side="top", fill="both", expand=True)

        self.toolbar = NavigationToolbar2Tk(self.renderer.canvas, canvas_frame)
        self.toolbar.update()
        self.toolbar.pack(side="bottom", fill="x")

        self.detail_frame = ttk.LabelFrame(self, text="Details", padding=8)
        self.detail_frame.pack(fill="x", padx=6, pady=6)
        self.detail_text = tk.StringVar(value="Select a node to view details.")
        self.detail_label = ttk.Label(
            self.detail_frame,
            textvariable=self.detail_text,
            anchor="w",
            justify="left",
            wraplength=600,
        )
        self.detail_label.pack(fill="x")
        self.detail_frame.bind("<Configure>", self._on_detail_resize)

        self.legend_frame = ttk.LabelFrame(self, text="Legend", padding=6)
        self.legend_frame.pack(fill="x", padx=6, pady=6)
        self._build_legend()

        self.renderer.canvas.mpl_connect("button_press_event", self._on_click)
        self.renderer.canvas.mpl_connect("motion_notify_event", self._on_hover)

    def set_options(self, stakeholders: List[str], requirements: List[str], test_cases: List[str]) -> None:
        self.filters_panel.set_stakeholders(stakeholders)
        self.filters_panel.set_requirements(requirements)
        self.filters_panel.set_test_cases(test_cases)

    def set_data(
        self,
        requirements: List[Requirement],
        test_cases: List[TestCase],
        results: List[AnalysisResult],
    ) -> None:
        self.requirements = {r.req_id: r for r in requirements}
        self.results_map = {r.req_id: r for r in results}
        self.test_cases = list(test_cases)
        self._render(preserve_view=False)

    def _build_legend(self) -> None:
        for child in self.legend_frame.winfo_children():
            child.destroy()
        theme = get_theme(self.filters_panel.theme_var.get())
        items = [
            ("System Requirement", theme.system_node),
            ("Test Case", theme.testcase_node),
            ("Test Step", theme.teststep_node),
            ("Covered Link", theme.link_covered),
            ("Uncovered Link", theme.link_uncovered),
        ]
        for i, (label, color) in enumerate(items):
            swatch = tk.Canvas(self.legend_frame, width=14, height=14, highlightthickness=0)
            swatch.create_rectangle(0, 0, 14, 14, fill=color, outline=color)
            swatch.grid(row=0, column=i * 2, padx=4, pady=2)
            ttk.Label(self.legend_frame, text=label).grid(row=0, column=i * 2 + 1, padx=4)

    def _on_filters_changed(self) -> None:
        self.selected_node = None
        self.renderer.hover_node = None
        self.renderer.selected_node = None
        self._render(preserve_view=False)

    def clear_selection(self) -> None:
        self.selected_node = None
        self.renderer.hover_node = None
        self.renderer.selected_node = None
        self._redraw_current(preserve_view=True)

    def export_image(self, fmt: str) -> None:
        from tkinter import filedialog

        filepath = filedialog.asksaveasfilename(
            title=f"Export {fmt.upper()}",
            defaultextension=f".{fmt}",
            filetypes=[(fmt.upper(), f"*.{fmt}")],
        )
        if not filepath:
            return
        self.renderer.export(filepath, fmt)

    def copy_to_clipboard(self) -> None:
        self.renderer.copy_to_clipboard()

    def _render(self, preserve_view: bool = False) -> None:
        filters = self.filters_panel.get_filters()
        view = filters["view"]
        theme = filters["theme"]
        stakeholder = filters["stakeholder"]
        prefix = filters["prefix"]
        coverage = filters["coverage"]
        selected_reqs = filters["requirements"]
        selected_test_case = filters["test_case"]

        self.renderer.set_theme(theme)
        self._build_legend()

        if view == "Requirements -> Test Cases":
            nodes, links = build_view1_data(
                list(self.requirements.values()),
                self.test_cases,
                list(self.results_map.values()),
                stakeholder,
                prefix,
                coverage,
                selected_reqs,
            )
            headers = ["System Requirements", "Test Cases"]
            banner = "TRACEABILITY VIEW - REQUIREMENTS TO TEST CASES"
            self.filters_panel.test_case_combo.configure(state="disabled")
        else:
            nodes, links = build_view2_data(
                list(self.requirements.values()),
                self.test_cases,
                list(self.results_map.values()),
                selected_test_case,
                stakeholder,
                prefix,
                coverage,
                selected_reqs,
            )
            headers = ["System Requirements", f"Test Case: {selected_test_case or '-'}", "Test Steps"]
            banner = f"TRACEABILITY VIEW - TEST CASE {selected_test_case or '-'}"
            self.filters_panel.test_case_combo.configure(state="readonly")

        theme_palette = get_theme(theme)
        self.banner_label.configure(background=theme_palette.banner_bg, foreground=theme_palette.text)
        for link in links:
            link.color = resolve_link_color(
                link.color,
                {"covered": theme_palette.link_covered, "uncovered": theme_palette.link_uncovered},
            )

        self.banner_var.set(banner)
        self.renderer.selected_node = self.selected_node
        self._last_nodes = nodes
        self._last_links = links
        self._last_headers = headers
        self.renderer.draw(nodes, links, headers, preserve_view=preserve_view)

    def _redraw_current(self, preserve_view: bool = True) -> None:
        if not self._last_nodes:
            self._render(preserve_view=preserve_view)
            return
        self.renderer.draw(self._last_nodes, self._last_links, self._last_headers, preserve_view=preserve_view)

    def _hit_test(self, event) -> Optional[str]:
        ctx = self.renderer.get_context()
        if event.xdata is None or event.ydata is None:
            return None
        for node_id, (x, y, w, h) in ctx.positions.items():
            if x <= event.xdata <= x + w and y <= event.ydata <= y + h:
                return node_id
        return None

    def _on_click(self, event) -> None:
        if getattr(self.toolbar, "mode", ""):
            return
        node_id = self._hit_test(event)
        if not node_id:
            return
        self.selected_node = node_id
        node = self.renderer.get_context().nodes[node_id]
        self._update_details(node)
        self.renderer.selected_node = self.selected_node
        self._redraw_current(preserve_view=True)

    def _on_hover(self, event) -> None:
        if getattr(self.toolbar, "mode", ""):
            return
        node_id = self._hit_test(event)
        if not node_id:
            if self.renderer.hover_node is not None:
                self.renderer.hover_node = None
                self._redraw_current(preserve_view=True)
            return
        node = self.renderer.get_context().nodes[node_id]
        if self.renderer.hover_node != node_id:
            self.renderer.hover_node = node_id
            self._redraw_current(preserve_view=True)
        self._update_details(node)

    def _update_details(self, node) -> None:
        if node.node_type == "system":
            stake = node.metadata.get("stakeholder") or "-"
            covered = "YES" if node.metadata.get("covered") else "NO"
            steps = sorted({tc.ts_id for tc in self.test_cases if tc.ref_id == node.label})
            step_text = ", ".join(steps) if steps else "-"
            self.detail_text.set(
                "System Requirement\n"
                f"ID: {node.label}\n"
                f"Stakeholder: {stake}\n"
                f"Source: {node.metadata.get('source') or '-'}\n"
                f"Covered: {covered}\n"
                f"Linked Steps: {step_text}"
            )
        elif node.node_type == "teststep":
            reqs = sorted({tc.ref_id for tc in self.test_cases if tc.ts_id == node.label})
            req_text = ", ".join(reqs) if reqs else "-"
            self.detail_text.set(
                "Test Step\n"
                f"ID: {node.label}\n"
                f"Source: {node.metadata.get('source') or '-'}\n"
                f"Validated Requirements: {req_text}\n"
                "Step Description: -\n"
                "Input: -\n"
                "Expected Output: -"
            )
        else:
            self.detail_text.set(
                "Test Case\n"
                f"ID: {node.label}\n"
                f"Source: {node.metadata.get('source') or '-'}"
            )

    def _on_detail_resize(self, event) -> None:
        self.detail_label.configure(wraplength=max(200, event.width - 20))
