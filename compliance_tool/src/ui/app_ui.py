import os
import re
from typing import List
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk

from src.backend.analysis_engine import analyze
from src.backend.document_manager import DocumentManager
from src.backend.exporter import export_analysis_csv
from src.backend.models import AnalysisResult, OrphanReference, Requirement, TestCase
from src.backend.parser import parse_requirements, parse_test_procedures
from src.backend.project_manager import ProjectManager
from src.ui.command_controller import CommandController
from src.ui.components import labeled_frame, make_tree
from src.ui.sankey_view import SankeyView
from src.utils.logger import get_logger


class ComplianceApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Compliance Analyzer - Phase 3")
        self.logger = get_logger(self.__class__.__name__)

        self.base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
        self.doc_manager = DocumentManager(self.base_dir)
        self.project_manager = ProjectManager(self.base_dir)
        self.commands = CommandController(self)

        self.requirements = {}
        self.test_cases = []
        self.results = []
        self.orphans = []
        self.summary = {}
        self.dirty = False
        self.coverage_row_colors = {}
        self._coverage_menu_iid = None

        self._build_ui()
        self._update_title()
        self.root.protocol("WM_DELETE_WINDOW", self.handle_exit)

    def _build_ui(self) -> None:
        self.root.geometry("1120x760")
        self.root.minsize(980, 700)

        self._build_menu()

        toolbar = ttk.Frame(self.root, padding=6)
        toolbar.pack(fill="x")

        ttk.Button(toolbar, text="Add Requirement Docs", command=self.commands.add_requirements).pack(side="left", padx=4)
        ttk.Button(toolbar, text="Add Test Procedure Docs", command=self.commands.add_tests).pack(side="left", padx=4)
        ttk.Button(toolbar, text="Run Analysis", command=self.commands.run_analysis).pack(side="left", padx=4)

        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(self.root, textvariable=self.status_var, anchor="w").pack(fill="x", padx=8, pady=2)

        notebook = ttk.Notebook(self.root)
        notebook.pack(fill="both", expand=True)

        self.coverage_frame = ttk.Frame(notebook)
        self.orphan_frame = ttk.Frame(notebook)
        self.summary_frame = ttk.Frame(notebook)
        self.trace_frame = ttk.Frame(notebook)

        notebook.add(self.coverage_frame, text="Requirements Coverage")
        notebook.add(self.orphan_frame, text="Orphan Test References")
        notebook.add(self.summary_frame, text="Summary")
        notebook.add(self.trace_frame, text="Traceability View")

        self._build_coverage_tab()
        self._build_orphan_tab()
        self._build_summary_tab()
        self._build_traceability_tab()

    def _build_menu(self) -> None:
        menubar = tk.Menu(self.root)
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="New Project", command=self.commands.new_project)
        file_menu.add_command(label="Open Project", command=self.commands.open_project)
        file_menu.add_command(label="Save Project", command=self.commands.save_project)
        file_menu.add_command(label="Save Project As", command=self.commands.save_project_as)
        file_menu.add_separator()
        file_menu.add_command(label="Export Analysis to CSV", command=self.commands.export_csv)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.commands.exit_app)
        menubar.add_cascade(label="File", menu=file_menu)
        self.root.config(menu=menubar)

    def _build_coverage_tab(self) -> None:
        frame = labeled_frame(self.coverage_frame, "Requirement Coverage")
        filters = ttk.Frame(frame)
        filters.pack(fill="x", padx=6, pady=4)

        self.coverage_filter_vars = {
            "stakeholder": tk.StringVar(),
            "requirement": tk.StringVar(),
            "covered": tk.StringVar(value="All"),
            "linked": tk.StringVar(),
        }

        ttk.Label(filters, text="Stakeholder ID").grid(row=0, column=0, sticky="w", padx=4, pady=2)
        ttk.Entry(filters, textvariable=self.coverage_filter_vars["stakeholder"], width=16).grid(
            row=0, column=1, sticky="w", padx=4, pady=2
        )

        ttk.Label(filters, text="Requirement ID").grid(row=0, column=2, sticky="w", padx=4, pady=2)
        ttk.Entry(filters, textvariable=self.coverage_filter_vars["requirement"], width=16).grid(
            row=0, column=3, sticky="w", padx=4, pady=2
        )

        ttk.Label(filters, text="Covered").grid(row=0, column=4, sticky="w", padx=4, pady=2)
        ttk.Combobox(
            filters,
            textvariable=self.coverage_filter_vars["covered"],
            values=["All", "YES", "NO"],
            state="readonly",
            width=8,
        ).grid(row=0, column=5, sticky="w", padx=4, pady=2)

        ttk.Label(filters, text="Linked Test Cases").grid(row=0, column=6, sticky="w", padx=4, pady=2)
        ttk.Entry(filters, textvariable=self.coverage_filter_vars["linked"], width=18).grid(
            row=0, column=7, sticky="w", padx=4, pady=2
        )

        ttk.Button(filters, text="Clear Filters", command=self._clear_coverage_filters).grid(
            row=0, column=8, sticky="w", padx=6, pady=2
        )

        for var in self.coverage_filter_vars.values():
            var.trace_add("write", lambda *_: self._refresh_coverage())

        self.coverage_tree = make_tree(
            frame,
            columns=["stakeholder", "req_id", "covered", "test_cases", "test_steps", "source_doc"],
            headings=[
                "Stakeholder ID",
                "Requirement ID",
                "Covered",
                "Test Case Number",
                "Linked Test Cases",
                "Source Document",
            ],
        )
        self._init_coverage_colors()

    def _init_coverage_colors(self) -> None:
        self.coverage_tree.tag_configure("color_red", background="#f5b7b1")
        self.coverage_tree.tag_configure("color_yellow", background="#f9e79f")
        self.coverage_tree.tag_configure("color_green", background="#abebc6")
        self.coverage_tree.tag_configure("color_blue", background="#aed6f1")
        self.coverage_tree.tag_configure("color_gray", background="#d5d8dc")

        menu = tk.Menu(self.root, tearoff=0)
        menu.add_command(label="Mark Red", command=lambda: self._set_coverage_row_color("color_red"))
        menu.add_command(label="Mark Yellow", command=lambda: self._set_coverage_row_color("color_yellow"))
        menu.add_command(label="Mark Green", command=lambda: self._set_coverage_row_color("color_green"))
        menu.add_command(label="Mark Blue", command=lambda: self._set_coverage_row_color("color_blue"))
        menu.add_command(label="Mark Gray", command=lambda: self._set_coverage_row_color("color_gray"))
        menu.add_separator()
        menu.add_command(label="Clear Color", command=self._clear_coverage_row_color)
        self.coverage_menu = menu

        self.coverage_tree.bind("<Button-3>", self._show_coverage_menu)
        self.coverage_tree.bind("<Button-2>", self._show_coverage_menu)

    def _build_orphan_tab(self) -> None:
        frame = labeled_frame(self.orphan_frame, "Orphan Test References")
        self.orphan_tree = make_tree(
            frame,
            columns=["ts_id", "ref_id", "source_doc"],
            headings=["Test Step ID", "Referenced Requirement", "Test Document"],
        )

    def _build_summary_tab(self) -> None:
        frame = labeled_frame(self.summary_frame, "Summary Dashboard")
        self.summary_vars = {
            "total_stakeholders": tk.StringVar(value="0"),
            "total_requirements": tk.StringVar(value="0"),
            "covered_requirements": tk.StringVar(value="0"),
            "uncovered_requirements": tk.StringVar(value="0"),
            "coverage_percent": tk.StringVar(value="0"),
        }

        rows = [
            ("Total Stakeholder Requirements", "total_stakeholders"),
            ("Total System Requirements", "total_requirements"),
            ("Covered Requirements", "covered_requirements"),
            ("Uncovered Requirements", "uncovered_requirements"),
            ("Coverage Percentage", "coverage_percent"),
        ]

        for i, (label, key) in enumerate(rows):
            ttk.Label(frame, text=label).grid(row=i, column=0, sticky="w", padx=6, pady=6)
            ttk.Label(frame, textvariable=self.summary_vars[key]).grid(row=i, column=1, sticky="w", padx=6, pady=6)

        ttk.Separator(frame, orient="horizontal").grid(row=len(rows), column=0, columnspan=2, sticky="ew", pady=6)
        ttk.Label(frame, text="Quick Filters").grid(row=len(rows) + 1, column=0, sticky="w", padx=6)
        btn_frame = ttk.Frame(frame)
        btn_frame.grid(row=len(rows) + 1, column=1, sticky="w", padx=6)
        ttk.Button(btn_frame, text="All", command=lambda: self._set_trace_coverage("All")).pack(side="left", padx=2)
        ttk.Button(btn_frame, text="Covered", command=lambda: self._set_trace_coverage("Covered")).pack(side="left", padx=2)
        ttk.Button(btn_frame, text="Uncovered", command=lambda: self._set_trace_coverage("Uncovered")).pack(side="left", padx=2)

    def _build_traceability_tab(self) -> None:
        self.sankey_view = SankeyView(self.trace_frame)
        self.sankey_view.pack(fill="both", expand=True)

    def _set_dirty(self, dirty: bool) -> None:
        self.dirty = dirty
        self._update_title()

    def _update_title(self) -> None:
        name = self.project_manager.project_name
        suffix = " *" if self.dirty else ""
        self.root.title(f"Compliance Analyzer - {name}{suffix}")

    def _set_trace_coverage(self, value: str) -> None:
        self.sankey_view.filters_panel.coverage_var.set(value)
        self._refresh_sankey()

    def handle_new_project(self) -> None:
        if not self._confirm_discard():
            return
        name = simpledialog.askstring("New Project", "Project name:")
        if name is None:
            return
        self.project_manager.new_project(name.strip() or "Untitled")
        self._reset_state()
        self._set_dirty(False)
        self.status_var.set("New project created")

    def handle_open_project(self) -> None:
        if not self._confirm_discard():
            return
        filepath = filedialog.askopenfilename(
            title="Open Compliance Project",
            filetypes=[("Compliance Project", "*.compliance"), ("All Files", "*.*")],
        )
        if not filepath:
            return

        payload, _ = self.project_manager.load_project(filepath)
        self._load_from_payload(payload)
        self._set_dirty(False)
        self.status_var.set(f"Opened project {filepath}")

    def handle_save_project(self) -> None:
        try:
            path = self.project_manager.save_project(
                None,
                self.doc_manager.list_documents("requirements"),
                self.doc_manager.list_documents("test_procedures"),
                list(self.requirements.values()),
                self.test_cases,
                self.results,
                self.orphans,
                self.summary,
            )
        except ValueError:
            self.handle_save_project_as()
            return

        self._set_dirty(False)
        self.status_var.set(f"Saved project to {path}")

    def handle_save_project_as(self) -> None:
        filepath = filedialog.asksaveasfilename(
            title="Save Compliance Project",
            defaultextension=".compliance",
            filetypes=[("Compliance Project", "*.compliance")],
        )
        if not filepath:
            return

        self.project_manager.save_project(
            filepath,
            self.doc_manager.list_documents("requirements"),
            self.doc_manager.list_documents("test_procedures"),
            list(self.requirements.values()),
            self.test_cases,
            self.results,
            self.orphans,
            self.summary,
        )
        self._set_dirty(False)
        self.status_var.set(f"Saved project to {filepath}")

    def handle_add_requirements(self) -> None:
        filepaths = filedialog.askopenfilenames(
            title="Select Requirement Documents",
            filetypes=[("Word Documents", "*.docx")],
        )
        if not filepaths:
            return

        added = 0
        for fp in filepaths:
            try:
                dest = self.doc_manager.add_document(fp, "requirements")
                reqs = parse_requirements(dest, source_label=fp)
                for req in reqs:
                    self.requirements.setdefault(req.req_id, req)
                added += 1
            except Exception as exc:
                self.logger.exception("Failed to add requirement doc")
                messagebox.showerror("Error", f"Failed to add {fp}: {exc}")

        if added:
            self._set_dirty(True)
        self._refresh_all_views()
        self.status_var.set(f"Added {added} requirement document(s)")

    def handle_add_tests(self) -> None:
        filepaths = filedialog.askopenfilenames(
            title="Select Test Procedure Documents",
            filetypes=[("Word Documents", "*.docx")],
        )
        if not filepaths:
            return

        added = 0
        for fp in filepaths:
            try:
                dest = self.doc_manager.add_document(fp, "test_procedures")
                test_cases = parse_test_procedures(dest, source_label=fp)
                self.test_cases.extend(test_cases)
                added += 1
            except Exception as exc:
                self.logger.exception("Failed to add test procedure doc")
                messagebox.showerror("Error", f"Failed to add {fp}: {exc}")

        if added:
            self._set_dirty(True)
        self._refresh_all_views()
        self.status_var.set(f"Added {added} test procedure document(s)")

    def handle_run_analysis(self) -> None:
        if not self.requirements:
            messagebox.showwarning("No Requirements", "Please add requirement documents first.")
            return
        if not self.test_cases:
            messagebox.showwarning("No Tests", "Please add test procedure documents first.")
            return

        self.results, self.orphans, self.summary = analyze(
            list(self.requirements.values()), self.test_cases
        )
        self._refresh_all_views()
        self._set_dirty(True)
        self.status_var.set("Analysis complete")

    def handle_export_csv(self) -> None:
        if not self.results:
            messagebox.showwarning("No Results", "Run analysis before exporting.")
            return
        filepath = filedialog.asksaveasfilename(
            title="Export Analysis to CSV",
            defaultextension=".csv",
            filetypes=[("CSV", "*.csv")],
        )
        if not filepath:
            return
        export_analysis_csv(filepath, self.results)
        self.status_var.set(f"Exported CSV to {filepath}")

    def handle_exit(self) -> None:
        if not self._confirm_discard():
            return
        self.doc_manager.cleanup()
        self.root.destroy()

    def _reset_state(self) -> None:
        self.requirements = {}
        self.test_cases = []
        self.results = []
        self.orphans = []
        self.summary = {}
        self.doc_manager.clear()
        self._refresh_all_views()

    def _load_from_payload(self, payload: dict) -> None:
        req_docs = [self.project_manager.resolve_path(p) for p in payload.get("requirement_documents", [])]
        test_docs = [self.project_manager.resolve_path(p) for p in payload.get("test_documents", [])]
        self.doc_manager.set_documents("requirements", req_docs)
        self.doc_manager.set_documents("test_procedures", test_docs)

        self.requirements = {}
        for item in payload.get("requirements", []):
            req = Requirement(
                req_id=item["id"],
                stakeholder_id=item.get("stakeholder"),
                source_doc=self.project_manager.resolve_path(item.get("source_document", "")),
            )
            self.requirements[req.req_id] = req

        self.test_cases = [
            TestCase(
                ts_id=tc["test_id"],
                ref_id=tc["requirement_id"],
                source_doc=self.project_manager.resolve_path(tc.get("source_document", "")),
                test_case_id=tc.get("test_case_id"),
                test_case_title=tc.get("test_case_title"),
            )
            for tc in payload.get("test_cases", [])
        ]

        self.results = []
        analysis = payload.get("analysis", {})
        for req_id, entry in analysis.items():
            self.results.append(
                AnalysisResult(
                    req_id=req_id,
                    stakeholder_id=entry.get("stakeholder"),
                    source_doc=self.project_manager.resolve_path(entry.get("source_document", "")),
                    covered=bool(entry.get("covered")),
                    test_steps=entry.get("test_cases", []),
                    test_cases=entry.get("test_case_numbers", []),
                )
            )

        self.orphans = [
            OrphanReference(
                ts_id=o["test_id"],
                ref_id=o["requirement_id"],
                source_doc=self.project_manager.resolve_path(o.get("source_document", "")),
            )
            for o in payload.get("orphan_references", [])
        ]

        self.summary = payload.get("summary", {})
        self._refresh_all_views()

    def _refresh_all_views(self) -> None:
        self._refresh_coverage()
        self._refresh_orphans()
        self._refresh_summary()
        self._refresh_sankey()

    def _refresh_coverage(self) -> None:
        for item in self.coverage_tree.get_children():
            self.coverage_tree.delete(item)
        if self.results:
            rows = self.results
        else:
            rows = [
                AnalysisResult(
                    req_id=req.req_id,
                    stakeholder_id=req.stakeholder_id,
                    source_doc=req.source_doc,
                    covered=False,
                    test_steps=[],
                    test_cases=[],
                )
                for req in self.requirements.values()
            ]
        filters = getattr(self, "coverage_filter_vars", None)
        if filters:
            stakeholder_filter = filters["stakeholder"].get().strip().lower()
            req_filter = filters["requirement"].get().strip().lower()
            covered_filter = filters["covered"].get().strip().upper()
            linked_filter = filters["linked"].get().strip().lower()

            def _matches(res: AnalysisResult) -> bool:
                stakeholder_val = (res.stakeholder_id or "").lower()
                req_val = (res.req_id or "").lower()
                covered_val = "YES" if res.covered else "NO"
                linked_val = ", ".join(res.test_steps).lower() if res.test_steps else ""

                if stakeholder_filter and stakeholder_filter not in stakeholder_val:
                    return False
                if req_filter and req_filter not in req_val:
                    return False
                if covered_filter in ("YES", "NO") and covered_val != covered_filter:
                    return False
                if linked_filter and linked_filter not in linked_val:
                    return False
                return True

            rows = [r for r in rows if _matches(r)]

        rows = sorted(
            rows,
            key=lambda r: (
                (r.stakeholder_id or "").lower(),
                (r.req_id or "").lower(),
                r.covered,
                ", ".join(r.test_cases).lower() if r.test_cases else "",
                ", ".join(r.test_steps).lower() if r.test_steps else "",
            ),
        )
        for res in rows:
            iid = self._coverage_row_key(res)
            covered = "YES" if res.covered else "NO"
            cases = self._format_test_case_label(res.test_cases)
            steps = ", ".join(res.test_steps) if res.test_steps else "-"
            tag = self.coverage_row_colors.get(iid)
            self.coverage_tree.insert(
                "",
                tk.END,
                iid=iid,
                values=(res.stakeholder_id or "", res.req_id, covered, cases, steps, res.source_doc),
                tags=([tag] if tag else []),
            )

    def _clear_coverage_filters(self) -> None:
        for key, var in self.coverage_filter_vars.items():
            if key == "covered":
                var.set("All")
            else:
                var.set("")

    @staticmethod
    def _coverage_row_key(res: AnalysisResult) -> str:
        stakeholder = res.stakeholder_id or ""
        source_doc = res.source_doc or ""
        return f"{res.req_id}||{stakeholder}||{source_doc}"

    def _show_coverage_menu(self, event: tk.Event) -> None:
        row_id = self.coverage_tree.identify_row(event.y)
        if not row_id:
            return
        self.coverage_tree.selection_set(row_id)
        self._coverage_menu_iid = row_id
        self.coverage_menu.tk_popup(event.x_root, event.y_root)

    def _set_coverage_row_color(self, tag: str) -> None:
        row_id = self._coverage_menu_iid
        if not row_id:
            return
        self.coverage_row_colors[row_id] = tag
        if self.coverage_tree.exists(row_id):
            self.coverage_tree.item(row_id, tags=[tag])

    def _clear_coverage_row_color(self) -> None:
        row_id = self._coverage_menu_iid
        if not row_id:
            return
        self.coverage_row_colors.pop(row_id, None)
        if self.coverage_tree.exists(row_id):
            self.coverage_tree.item(row_id, tags=[])

    @staticmethod
    def _normalize_test_case_label(label: str) -> str:
        normalized = " ".join((label or "").strip().split())
        if not normalized:
            return normalized
        if normalized.lower().startswith("test case"):
            return normalized
        return f"Test Case {normalized}"

    def _format_test_case_label(self, labels: List[str]) -> str:
        if not labels:
            return "-"
        normalized = [self._normalize_test_case_label(c) for c in labels if c]
        if not normalized:
            return "-"
        normalized = sorted(set(normalized), key=self._test_case_sort_key)
        return normalized[0]

    @staticmethod
    def _test_case_sort_key(label: str) -> tuple:
        match = re.search(r"test case\s+(\d+)", label, re.IGNORECASE)
        if match:
            return (0, int(match.group(1)), label.lower())
        return (1, 10**9, label.lower())

    def _refresh_orphans(self) -> None:
        for item in self.orphan_tree.get_children():
            self.orphan_tree.delete(item)
        for orphan in self.orphans:
            self.orphan_tree.insert(
                "",
                tk.END,
                values=(orphan.ts_id, orphan.ref_id, orphan.source_doc),
            )

    def _refresh_summary(self) -> None:
        summary = self.summary or {}
        stakeholders = {req.stakeholder_id for req in self.requirements.values() if req.stakeholder_id}
        self.summary_vars["total_stakeholders"].set(len(stakeholders))
        self.summary_vars["total_requirements"].set(summary.get("total_requirements", len(self.requirements)))
        self.summary_vars["covered_requirements"].set(summary.get("covered_requirements", 0))
        self.summary_vars["uncovered_requirements"].set(summary.get("uncovered_requirements", 0))
        coverage_pct = summary.get("coverage_percent", 0)
        self.summary_vars["coverage_percent"].set(f"{coverage_pct}%")

    def _refresh_sankey(self) -> None:
        stakeholders = sorted({req.stakeholder_id for req in self.requirements.values() if req.stakeholder_id})
        requirement_ids = sorted(self.requirements.keys())
        test_cases = sorted({tc.ts_id.split(".")[0] for tc in self.test_cases if tc.ts_id})
        self.sankey_view.set_options(stakeholders, requirement_ids, test_cases)
        self.sankey_view.set_data(list(self.requirements.values()), self.test_cases, self.results)

    def _confirm_discard(self) -> bool:
        if not self.dirty:
            return True
        response = messagebox.askyesnocancel(
            "Unsaved Changes",
            "You have unsaved changes. Save before continuing?",
        )
        if response is None:
            return False
        if response:
            self.handle_save_project()
            return not self.dirty
        return True


def run_app() -> None:
    root = tk.Tk()
    app = ComplianceApp(root)
    root.mainloop()
