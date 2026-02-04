import json
import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from src.backend.analysis_engine import analyze
from src.backend.document_manager import DocumentManager
from src.backend.models import AnalysisResult, Requirement, TestCase
from src.backend.parser import parse_requirements, parse_test_procedures
from src.ui.components import labeled_frame, make_listbox, make_tree
from src.utils.logger import get_logger


class ComplianceApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Compliance Analyzer - Phase 1")
        self.logger = get_logger(self.__class__.__name__)

        base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
        self.doc_manager = DocumentManager(base_dir)

        self.requirements = {}
        self.test_cases = []
        self.results = []

        self._build_ui()

    def _build_ui(self) -> None:
        self.root.geometry("900x650")
        self.root.minsize(800, 600)

        toolbar = ttk.Frame(self.root, padding=6)
        toolbar.pack(fill="x")

        ttk.Button(toolbar, text="Add Requirement Docs", command=self.add_requirements).pack(side="left", padx=4)
        ttk.Button(toolbar, text="Add Test Procedure Docs", command=self.add_tests).pack(side="left", padx=4)
        ttk.Button(toolbar, text="Run Analysis", command=self.run_analysis).pack(side="left", padx=4)
        ttk.Button(toolbar, text="Save Analysis", command=self.save_analysis).pack(side="left", padx=4)
        ttk.Button(toolbar, text="Load Analysis", command=self.load_analysis).pack(side="left", padx=4)

        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(self.root, textvariable=self.status_var, anchor="w").pack(fill="x", padx=8, pady=2)

        notebook = ttk.Notebook(self.root)
        notebook.pack(fill="both", expand=True)

        self.req_frame = ttk.Frame(notebook)
        self.test_frame = ttk.Frame(notebook)
        self.report_frame = ttk.Frame(notebook)

        notebook.add(self.req_frame, text="Requirements")
        notebook.add(self.test_frame, text="Test Cases")
        notebook.add(self.report_frame, text="Report")

        self._build_requirements_tab()
        self._build_tests_tab()
        self._build_report_tab()

    def _build_requirements_tab(self) -> None:
        frame = labeled_frame(self.req_frame, "Parsed Requirement IDs")
        self.req_listbox = make_listbox(frame, height=20)

    def _build_tests_tab(self) -> None:
        frame = labeled_frame(self.test_frame, "Parsed Test Steps")
        self.test_listbox = make_listbox(frame, height=20)

    def _build_report_tab(self) -> None:
        frame = labeled_frame(self.report_frame, "Compliance Results")
        self.report_tree = make_tree(
            frame,
            columns=["req_id", "covered", "test_steps"],
            headings=["Requirement", "Covered", "Test Cases"],
        )

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
                reqs = parse_requirements(dest, include_stakeholder=False)
                for req in reqs:
                    self.requirements.setdefault(req.req_id, req)
                added += 1
            except Exception as exc:
                self.logger.exception("Failed to add requirement doc")
                messagebox.showerror("Error", f"Failed to add {fp}: {exc}")

        self._refresh_requirements()
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

        self._refresh_tests()
        self.status_var.set(f"Added {added} test procedure document(s)")

    def run_analysis(self) -> None:
        if not self.requirements:
            messagebox.showwarning("No Requirements", "Please add requirement documents first.")
            return
        if not self.test_cases:
            messagebox.showwarning("No Tests", "Please add test procedure documents first.")
            return

        self.results = analyze(self.requirements.values(), self.test_cases)
        self._refresh_report()
        self.status_var.set("Analysis complete")

    def save_analysis(self) -> None:
        if not self.results:
            messagebox.showwarning("No Results", "Run analysis before saving.")
            return

        filepath = filedialog.asksaveasfilename(
            title="Save Analysis",
            defaultextension=".json",
            filetypes=[("JSON", "*.json")],
        )
        if not filepath:
            return

        payload = {
            "requirements": [r.req_id for r in self.requirements.values()],
            "test_cases": [
                {"ts_id": tc.ts_id, "ref_id": tc.ref_id, "source_doc": tc.source_doc}
                for tc in self.test_cases
            ],
            "results": [
                {"req_id": r.req_id, "covered": r.covered, "test_steps": r.test_steps}
                for r in self.results
            ],
        }

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)

        self.status_var.set(f"Saved analysis to {filepath}")

    def load_analysis(self) -> None:
        filepath = filedialog.askopenfilename(
            title="Load Analysis",
            filetypes=[("JSON", "*.json")],
        )
        if not filepath:
            return

        with open(filepath, "r", encoding="utf-8") as f:
            payload = json.load(f)

        self.requirements = {req_id: Requirement(req_id=req_id, source_doc="(loaded)") for req_id in payload.get("requirements", [])}
        self.test_cases = [
            TestCase(ts_id=tc["ts_id"], ref_id=tc["ref_id"], source_doc=tc.get("source_doc", "(loaded)"))
            for tc in payload.get("test_cases", [])
        ]
        self.results = [
            AnalysisResult(
                req_id=item["req_id"],
                covered=bool(item["covered"]),
                test_steps=item.get("test_steps", []),
            )
            for item in payload.get("results", [])
        ]

        self._refresh_requirements()
        self._refresh_tests()
        self._refresh_report()
        self.status_var.set(f"Loaded analysis from {filepath}")

    def _refresh_requirements(self) -> None:
        self.req_listbox.delete(0, tk.END)
        for req_id in sorted(self.requirements.keys()):
            self.req_listbox.insert(tk.END, req_id)

    def _refresh_tests(self) -> None:
        self.test_listbox.delete(0, tk.END)
        for tc in self.test_cases:
            self.test_listbox.insert(tk.END, f"{tc.ts_id} -> {tc.ref_id}")

    def _refresh_report(self) -> None:
        for item in self.report_tree.get_children():
            self.report_tree.delete(item)
        for res in self.results:
            covered = "YES" if res.covered else "NO"
            steps = ", ".join(res.test_steps) if res.test_steps else "-"
            self.report_tree.insert("", tk.END, values=(res.req_id, covered, steps))


def run_app() -> None:
    root = tk.Tk()
    app = ComplianceApp(root)
    root.mainloop()
