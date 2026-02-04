import os
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk

from src.backend.analysis_engine import analyze
from src.backend.document_manager import DocumentManager
from src.backend.exporter import export_analysis_csv
from src.backend.models import AnalysisResult, OrphanReference, Requirement, TestCase
from src.backend.parser import parse_requirements, parse_test_procedures
from src.backend.project_manager import ProjectManager
from src.ui.components import labeled_frame, make_tree
from src.utils.logger import get_logger


class ComplianceApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Compliance Analyzer - Phase 2")
        self.logger = get_logger(self.__class__.__name__)

        self.base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
        self.doc_manager = DocumentManager(self.base_dir)
        self.project_manager = ProjectManager(self.base_dir)

        self.requirements = {}
        self.test_cases = []
        self.results = []
        self.orphans = []
        self.summary = {}
        self.dirty = False

        self._build_ui()
        self._update_title()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _build_ui(self) -> None:
        self.root.geometry("1020x700")
        self.root.minsize(900, 650)

        self._build_menu()

        toolbar = ttk.Frame(self.root, padding=6)
        toolbar.pack(fill="x")

        ttk.Button(toolbar, text="New Project", command=self.new_project).pack(side="left", padx=4)
        ttk.Button(toolbar, text="Open Project", command=self.open_project).pack(side="left", padx=4)
        ttk.Button(toolbar, text="Save Project", command=self.save_project).pack(side="left", padx=4)
        ttk.Button(toolbar, text="Save As", command=self.save_project_as).pack(side="left", padx=4)
        ttk.Separator(toolbar, orient="vertical").pack(side="left", fill="y", padx=6)
        ttk.Button(toolbar, text="Add Requirement Docs", command=self.add_requirements).pack(side="left", padx=4)
        ttk.Button(toolbar, text="Add Test Procedure Docs", command=self.add_tests).pack(side="left", padx=4)
        ttk.Button(toolbar, text="Run Analysis", command=self.run_analysis).pack(side="left", padx=4)
        ttk.Button(toolbar, text="Export CSV", command=self.export_csv).pack(side="left", padx=4)

        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(self.root, textvariable=self.status_var, anchor="w").pack(fill="x", padx=8, pady=2)

        notebook = ttk.Notebook(self.root)
        notebook.pack(fill="both", expand=True)

        self.coverage_frame = ttk.Frame(notebook)
        self.orphan_frame = ttk.Frame(notebook)
        self.summary_frame = ttk.Frame(notebook)

        notebook.add(self.coverage_frame, text="Requirements Coverage")
        notebook.add(self.orphan_frame, text="Orphan Test References")
        notebook.add(self.summary_frame, text="Summary")

        self._build_coverage_tab()
        self._build_orphan_tab()
        self._build_summary_tab()

    def _build_menu(self) -> None:
        menubar = tk.Menu(self.root)
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="New Project", command=self.new_project)
        file_menu.add_command(label="Open Project", command=self.open_project)
        file_menu.add_command(label="Save Project", command=self.save_project)
        file_menu.add_command(label="Save Project As", command=self.save_project_as)
        file_menu.add_separator()
        file_menu.add_command(label="Export Analysis to CSV", command=self.export_csv)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self._on_close)
        menubar.add_cascade(label="File", menu=file_menu)
        self.root.config(menu=menubar)

    def _build_coverage_tab(self) -> None:
        frame = labeled_frame(self.coverage_frame, "Requirement Coverage")
        self.coverage_tree = make_tree(
            frame,
            columns=["req_id", "stakeholder", "covered", "test_steps", "source_doc"],
            headings=["Requirement ID", "Stakeholder ID", "Covered", "Linked Test Cases", "Source Document"],
        )

    def _build_orphan_tab(self) -> None:
        frame = labeled_frame(self.orphan_frame, "Orphan Test References")
        self.orphan_tree = make_tree(
            frame,
            columns=["ts_id", "ref_id", "source_doc"],
            headings=["Test Step ID", "Referenced Requirement", "Test Document"],
        )

    def _build_summary_tab(self) -> None:
        frame = labeled_frame(self.summary_frame, "Summary")
        self.summary_vars = {
            "total_requirements": tk.StringVar(value="0"),
            "covered_requirements": tk.StringVar(value="0"),
            "uncovered_requirements": tk.StringVar(value="0"),
            "coverage_percent": tk.StringVar(value="0"),
        }

        rows = [
            ("Total Requirements", "total_requirements"),
            ("Covered Requirements", "covered_requirements"),
            ("Uncovered Requirements", "uncovered_requirements"),
            ("Coverage Percentage", "coverage_percent"),
        ]

        for i, (label, key) in enumerate(rows):
            ttk.Label(frame, text=label).grid(row=i, column=0, sticky="w", padx=6, pady=6)
            ttk.Label(frame, textvariable=self.summary_vars[key]).grid(row=i, column=1, sticky="w", padx=6, pady=6)

    def _set_dirty(self, dirty: bool) -> None:
        self.dirty = dirty
        self._update_title()

    def _update_title(self) -> None:
        name = self.project_manager.project_name
        suffix = " *" if self.dirty else ""
        self.root.title(f"Compliance Analyzer - {name}{suffix}")

    def new_project(self) -> None:
        if not self._confirm_discard():
            return
        name = simpledialog.askstring("New Project", "Project name:")
        if name is None:
            return
        self.project_manager.new_project(name.strip() or "Untitled")
        self._reset_state()
        self._set_dirty(False)
        self.status_var.set("New project created")

    def open_project(self) -> None:
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

    def save_project(self) -> None:
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
            self.save_project_as()
            return

        self._set_dirty(False)
        self.status_var.set(f"Saved project to {path}")

    def save_project_as(self) -> None:
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

    def add_requirements(self) -> None:
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
                reqs = parse_requirements(dest)
                for req in reqs:
                    self.requirements.setdefault(req.req_id, req)
                added += 1
            except Exception as exc:
                self.logger.exception("Failed to add requirement doc")
                messagebox.showerror("Error", f"Failed to add {fp}: {exc}")

        if added:
            self._set_dirty(True)
        self._refresh_coverage()
        self.status_var.set(f"Added {added} requirement document(s)")

    def add_tests(self) -> None:
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
                test_cases = parse_test_procedures(dest)
                self.test_cases.extend(test_cases)
                added += 1
            except Exception as exc:
                self.logger.exception("Failed to add test procedure doc")
                messagebox.showerror("Error", f"Failed to add {fp}: {exc}")

        if added:
            self._set_dirty(True)
        self._refresh_orphans()
        self.status_var.set(f"Added {added} test procedure document(s)")

    def run_analysis(self) -> None:
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

    def export_csv(self) -> None:
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
                )
                for req in self.requirements.values()
            ]
        for res in rows:
            covered = "YES" if res.covered else "NO"
            steps = ", ".join(res.test_steps) if res.test_steps else "-"
            self.coverage_tree.insert(
                "",
                tk.END,
                values=(res.req_id, res.stakeholder_id or "", covered, steps, res.source_doc),
            )

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
        self.summary_vars["total_requirements"].set(summary.get("total_requirements", 0))
        self.summary_vars["covered_requirements"].set(summary.get("covered_requirements", 0))
        self.summary_vars["uncovered_requirements"].set(summary.get("uncovered_requirements", 0))
        coverage_pct = summary.get("coverage_percent", 0)
        self.summary_vars["coverage_percent"].set(f"{coverage_pct}%")

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
            self.save_project()
            return not self.dirty
        return True

    def _on_close(self) -> None:
        if not self._confirm_discard():
            return
        self.root.destroy()


def run_app() -> None:
    root = tk.Tk()
    app = ComplianceApp(root)
    root.mainloop()
