
import os
import re
from collections import defaultdict
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Set

from PySide6.QtCore import QAbstractTableModel, QModelIndex, QObject, Qt, QSortFilterProxyModel
from PySide6.QtGui import QAction, QCloseEvent, QStandardItem, QStandardItemModel
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QDialog,
    QFileDialog,
    QFormLayout,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QListWidget,
    QMainWindow,
    QMenuBar,
    QMessageBox,
    QPushButton,
    QPlainTextEdit,
    QStatusBar,
    QTabWidget,
    QTableView,
    QTextEdit,
    QTreeView,
    QVBoxLayout,
    QWidget,
    QDockWidget,
)

from src.backend.analysis_engine import analyze
from src.backend.document_manager import DocumentManager
from src.backend.exporter import export_analysis_csv
from src.backend.models import AnalysisResult, OrphanReference, Requirement, TestCase
from src.backend.parser import parse_requirements, parse_test_procedures
from src.backend.project_manager import ProjectManager
from src.ui.command_controller import CommandController
from src.utils.logger import get_logger

ROLE_PAYLOAD = Qt.UserRole + 1


@dataclass
class GlobalFilterState:
    stakeholder: str = ""
    requirement: str = ""
    test_case: str = ""
    coverage: str = "All"
    prefix: str = ""


def _norm(value: str) -> str:
    return (value or "").strip().lower()


def _matches_substring(filter_text: str, value: str) -> bool:
    return not filter_text or filter_text in (value or "").lower()


def _matches_prefix(prefix_filter: str, values: Sequence[str]) -> bool:
    if not prefix_filter:
        return True
    for value in values:
        if (value or "").lower().startswith(prefix_filter):
            return True
    return False


class RequirementsMatrixModel(QAbstractTableModel):
    HEADERS = [
        "Stakeholder ID",
        "Requirement ID",
        "Coverage",
        "Test Case Number",
        "Linked Test Steps",
        "Source Document",
    ]

    def __init__(self, parent: Optional[QObject] = None):
        super().__init__(parent)
        self._rows: List[AnalysisResult] = []

    def set_rows(self, rows: List[AnalysisResult]) -> None:
        self.beginResetModel()
        self._rows = list(rows)
        self.endResetModel()

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        if parent.isValid():
            return 0
        return len(self._rows)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return len(self.HEADERS)

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.DisplayRole):
        if role != Qt.DisplayRole:
            return None
        if orientation == Qt.Horizontal:
            return self.HEADERS[section]
        return str(section + 1)

    def data(self, index: QModelIndex, role: int = Qt.DisplayRole):
        if not index.isValid():
            return None
        row = self._rows[index.row()]
        if role == ROLE_PAYLOAD:
            return row
        if role != Qt.DisplayRole:
            return None
        col = index.column()
        if col == 0:
            return row.stakeholder_id or ""
        if col == 1:
            return row.req_id
        if col == 2:
            return "YES" if row.covered else "NO"
        if col == 3:
            return self._format_test_case_numbers(row.test_cases)
        if col == 4:
            return ", ".join(row.test_steps) if row.test_steps else "-"
        if col == 5:
            return row.source_doc
        return None

    def sort(self, column: int, order: Qt.SortOrder = Qt.AscendingOrder) -> None:
        reverse = order == Qt.DescendingOrder
        self.layoutAboutToBeChanged.emit()
        self._rows.sort(key=lambda row: self._sort_key(row, column), reverse=reverse)
        self.layoutChanged.emit()

    def row_at(self, row: int) -> Optional[AnalysisResult]:
        if row < 0 or row >= len(self._rows):
            return None
        return self._rows[row]

    @staticmethod
    def _sort_key(row: AnalysisResult, column: int):
        if column == 0:
            return _norm(row.stakeholder_id or "")
        if column == 1:
            return _norm(row.req_id)
        if column == 2:
            return 0 if row.covered else 1
        if column == 3:
            numbers = RequirementsMatrixModel._extract_test_case_numbers(row.test_cases)
            if numbers:
                return (0, tuple(numbers))
            return (1, _norm(", ".join(row.test_cases)))
        if column == 4:
            return _norm(", ".join(row.test_steps))
        if column == 5:
            return _norm(row.source_doc)
        return ""

    @staticmethod
    def _normalize_test_case_label(label: str) -> str:
        normalized = " ".join((label or "").strip().split())
        if not normalized:
            return normalized
        if normalized.lower().startswith("test case"):
            return normalized
        return f"Test Case {normalized}"

    @classmethod
    def _extract_test_case_numbers(cls, labels: List[str]) -> List[int]:
        values: Set[int] = set()
        for label in labels or []:
            normalized = cls._normalize_test_case_label(label)
            match = re.search(r"test case\s+(\d+)", normalized, re.IGNORECASE)
            if match:
                values.add(int(match.group(1)))
                continue
            fallback = re.search(r"^\s*(\d+)\s*$", label or "")
            if fallback:
                values.add(int(fallback.group(1)))
        return sorted(values)

    @classmethod
    def _format_test_case_numbers(cls, labels: List[str]) -> str:
        numbers = cls._extract_test_case_numbers(labels)
        if not numbers:
            return "-"
        return ", ".join(str(n) for n in numbers)

    @staticmethod
    def _test_case_sort_key(label: str) -> tuple:
        match = re.search(r"test case\s+(\d+)", label, re.IGNORECASE)
        if match:
            return (0, int(match.group(1)), label.lower())
        return (1, 10**9, label.lower())


class OrphanModel(QAbstractTableModel):
    HEADERS = ["Test Step ID", "Referenced Requirement", "Test Document"]

    def __init__(self, parent: Optional[QObject] = None):
        super().__init__(parent)
        self._rows: List[OrphanReference] = []

    def set_rows(self, rows: List[OrphanReference]) -> None:
        self.beginResetModel()
        self._rows = list(rows)
        self.endResetModel()

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        if parent.isValid():
            return 0
        return len(self._rows)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return len(self.HEADERS)

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.DisplayRole):
        if role != Qt.DisplayRole:
            return None
        if orientation == Qt.Horizontal:
            return self.HEADERS[section]
        return str(section + 1)

    def data(self, index: QModelIndex, role: int = Qt.DisplayRole):
        if not index.isValid():
            return None
        row = self._rows[index.row()]
        if role == ROLE_PAYLOAD:
            return row
        if role != Qt.DisplayRole:
            return None
        if index.column() == 0:
            return row.ts_id
        if index.column() == 1:
            return row.ref_id
        if index.column() == 2:
            return row.source_doc
        return None

    def sort(self, column: int, order: Qt.SortOrder = Qt.AscendingOrder) -> None:
        reverse = order == Qt.DescendingOrder
        self.layoutAboutToBeChanged.emit()
        self._rows.sort(
            key=lambda row: (
                _norm(row.ts_id) if column == 0 else _norm(row.ref_id) if column == 1 else _norm(row.source_doc)
            ),
            reverse=reverse,
        )
        self.layoutChanged.emit()

    def row_at(self, row: int) -> Optional[OrphanReference]:
        if row < 0 or row >= len(self._rows):
            return None
        return self._rows[row]


class StakeholderOverviewModel(QAbstractTableModel):
    HEADERS = [
        "Stakeholder ID",
        "Requirements",
        "Covered",
        "Uncovered",
        "Coverage %",
        "Linked Test Cases",
    ]

    def __init__(self, parent: Optional[QObject] = None):
        super().__init__(parent)
        self._rows: List[dict] = []

    def set_rows(self, rows: List[dict]) -> None:
        self.beginResetModel()
        self._rows = rows
        self.endResetModel()

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        if parent.isValid():
            return 0
        return len(self._rows)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return len(self.HEADERS)

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.DisplayRole):
        if role != Qt.DisplayRole:
            return None
        if orientation == Qt.Horizontal:
            return self.HEADERS[section]
        return str(section + 1)

    def data(self, index: QModelIndex, role: int = Qt.DisplayRole):
        if not index.isValid():
            return None
        row = self._rows[index.row()]
        if role == ROLE_PAYLOAD:
            return row
        if role != Qt.DisplayRole:
            return None
        col = index.column()
        if col == 0:
            return row["stakeholder_id"]
        if col == 1:
            return row["requirements"]
        if col == 2:
            return row["covered"]
        if col == 3:
            return row["uncovered"]
        if col == 4:
            return f"{row['coverage_pct']:.2f}%"
        if col == 5:
            return ", ".join(row["test_cases"]) if row["test_cases"] else "-"
        return None

    def sort(self, column: int, order: Qt.SortOrder = Qt.AscendingOrder) -> None:
        reverse = order == Qt.DescendingOrder
        self.layoutAboutToBeChanged.emit()
        self._rows.sort(
            key=lambda row: (
                _norm(row["stakeholder_id"])
                if column == 0
                else row["requirements"]
                if column == 1
                else row["covered"]
                if column == 2
                else row["uncovered"]
                if column == 3
                else row["coverage_pct"]
                if column == 4
                else _norm(", ".join(row["test_cases"]))
            ),
            reverse=reverse,
        )
        self.layoutChanged.emit()

    def row_at(self, row: int) -> Optional[dict]:
        if row < 0 or row >= len(self._rows):
            return None
        return self._rows[row]


class GlobalFilterProxy(QSortFilterProxyModel):
    def __init__(self, view_name: str, parent: Optional[QObject] = None):
        super().__init__(parent)
        self.view_name = view_name
        self.state = GlobalFilterState()
        self.setDynamicSortFilter(True)
        self.setRecursiveFilteringEnabled(True)

    def set_filter_state(self, state: GlobalFilterState) -> None:
        self.state = state
        self.invalidateFilter()

    def filterAcceptsRow(self, source_row: int, source_parent: QModelIndex) -> bool:
        model = self.sourceModel()
        if model is None:
            return True

        if self.view_name == "explorer":
            if source_parent.isValid():
                return True
            index = model.index(source_row, 0, source_parent)
            payload = index.data(ROLE_PAYLOAD) or {}
            return self._matches_payload(payload)

        row_obj = None
        if hasattr(model, "row_at"):
            row_obj = model.row_at(source_row)
        if row_obj is None:
            return True
        payload = self._payload_from_row(row_obj)
        return self._matches_payload(payload)

    def _payload_from_row(self, row_obj) -> dict:
        if self.view_name == "requirements":
            return {
                "stakeholder": row_obj.stakeholder_id or "",
                "requirement": row_obj.req_id or "",
                "test_case": " ".join(row_obj.test_cases or []),
                "coverage": "YES" if row_obj.covered else "NO",
                "prefix_values": [row_obj.req_id, row_obj.stakeholder_id] + list(row_obj.test_steps) + list(row_obj.test_cases),
            }
        if self.view_name == "orphans":
            return {
                "stakeholder": "",
                "requirement": row_obj.ref_id or "",
                "test_case": row_obj.ts_id or "",
                "coverage": "NO",
                "prefix_values": [row_obj.ref_id, row_obj.ts_id],
            }
        if self.view_name == "stakeholders":
            return {
                "stakeholder": row_obj["stakeholder_id"],
                "requirement": " ".join(row_obj["requirement_ids"]),
                "test_case": " ".join(row_obj["test_cases"]),
                "coverage": "YES" if row_obj["uncovered"] == 0 else "NO",
                "prefix_values": [row_obj["stakeholder_id"]] + row_obj["requirement_ids"] + row_obj["test_cases"],
            }
        return {}

    def _matches_payload(self, payload: dict) -> bool:
        stakeholder_filter = _norm(self.state.stakeholder)
        requirement_filter = _norm(self.state.requirement)
        test_case_filter = _norm(self.state.test_case)
        coverage_filter = (self.state.coverage or "All").upper()
        prefix_filter = _norm(self.state.prefix)

        if not _matches_substring(stakeholder_filter, payload.get("stakeholder", "")):
            return False
        if not _matches_substring(requirement_filter, payload.get("requirement", "")):
            return False
        if not _matches_substring(test_case_filter, payload.get("test_case", "")):
            return False
        if coverage_filter in ("YES", "NO") and payload.get("coverage", "All").upper() != coverage_filter:
            return False
        if not _matches_prefix(prefix_filter, payload.get("prefix_values", [])):
            return False
        return True


class ComplianceApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.logger = get_logger(self.__class__.__name__)
        self.base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
        self.doc_manager = DocumentManager(self.base_dir)
        self.project_manager = ProjectManager(self.base_dir)
        self.commands = CommandController(self)

        self.requirements: Dict[str, Requirement] = {}
        self.test_cases: List[TestCase] = []
        self.results: List[AnalysisResult] = []
        self.orphans: List[OrphanReference] = []
        self.summary: dict = {}
        self.config_requirements: Set[str] = set()
        self.dirty = False

        self._build_ui()
        self._update_title()
        self._refresh_all_views()

    def _build_ui(self) -> None:
        self.resize(1240, 820)
        self.setMinimumSize(1040, 720)
        self._build_menu()

        central = QWidget(self)
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)

        toolbar = QHBoxLayout()
        buttons = [
            ("Add Requirement Docs", self.commands.add_requirements),
            ("Add Test Procedure Docs", self.commands.add_tests),
            ("Run Analysis", self.commands.run_analysis),
            ("Config Requirements", self._open_config_requirements),
        ]
        for text, callback in buttons:
            btn = QPushButton(text)
            btn.clicked.connect(callback)
            toolbar.addWidget(btn)
        toolbar.addStretch()
        layout.addLayout(toolbar)

        filter_panel = QFrame()
        filter_grid = QGridLayout(filter_panel)
        filter_grid.setContentsMargins(8, 6, 8, 6)
        filter_grid.setHorizontalSpacing(10)
        self.filter_stakeholder = QLineEdit()
        self.filter_requirement = QLineEdit()
        self.filter_test_case = QLineEdit()
        self.filter_coverage = QComboBox()
        self.filter_coverage.addItems(["All", "YES", "NO"])
        self.filter_prefix = QLineEdit()
        clear_btn = QPushButton("Clear Filters")
        clear_btn.clicked.connect(self._clear_global_filters)

        fields = [
            ("Stakeholder ID", self.filter_stakeholder),
            ("Requirement ID", self.filter_requirement),
            ("Test Case Number", self.filter_test_case),
            ("Coverage Status", self.filter_coverage),
            ("Prefix", self.filter_prefix),
        ]
        for i, (label, widget) in enumerate(fields):
            filter_grid.addWidget(QLabel(label), 0, i * 2)
            filter_grid.addWidget(widget, 0, i * 2 + 1)
        filter_grid.addWidget(clear_btn, 0, len(fields) * 2)
        layout.addWidget(filter_panel)

        self.tabs = QTabWidget()
        layout.addWidget(self.tabs, 1)

        self.test_case_tab = QWidget()
        self.requirements_tab = QWidget()
        self.stakeholder_tab = QWidget()
        self.orphan_tab = QWidget()
        self.summary_tab = QWidget()

        self.tabs.addTab(self.test_case_tab, "Test Case Explorer")
        self.tabs.addTab(self.requirements_tab, "Requirements Matrix")
        self.tabs.addTab(self.stakeholder_tab, "Stakeholder Overview")
        self.tabs.addTab(self.orphan_tab, "Orphan Test References")
        self.tabs.addTab(self.summary_tab, "Summary Dashboard")
        self.tabs.setCurrentIndex(0)

        self._build_test_case_tab()
        self._build_requirements_tab()
        self._build_stakeholder_tab()
        self._build_orphan_tab()
        self._build_summary_tab()

        self.detail_dock = QDockWidget("Details", self)
        self.detail_dock.setAllowedAreas(Qt.RightDockWidgetArea | Qt.LeftDockWidgetArea)
        self.detail_text = QTextEdit()
        self.detail_text.setReadOnly(True)
        self.detail_dock.setWidget(self.detail_text)
        self.addDockWidget(Qt.RightDockWidgetArea, self.detail_dock)

        status = QStatusBar(self)
        self.setStatusBar(status)
        self.statusBar().showMessage("Ready")

        self.filter_stakeholder.textChanged.connect(self._apply_global_filters)
        self.filter_requirement.textChanged.connect(self._apply_global_filters)
        self.filter_test_case.textChanged.connect(self._apply_global_filters)
        self.filter_coverage.currentTextChanged.connect(self._apply_global_filters)
        self.filter_prefix.textChanged.connect(self._apply_global_filters)
        self.tabs.currentChanged.connect(lambda _: self._update_detail_for_current_tab())

    def _build_menu(self) -> None:
        menubar = QMenuBar(self)
        self.setMenuBar(menubar)
        file_menu = menubar.addMenu("File")

        actions = [
            ("New Project", self.commands.new_project),
            ("Open Project", self.commands.open_project),
            ("Save Project", self.commands.save_project),
            ("Save Project As", self.commands.save_project_as),
            ("Export Analysis to CSV", self.commands.export_csv),
            ("Exit", self.commands.exit_app),
        ]
        for i, (label, callback) in enumerate(actions):
            if i in (4, 5):
                file_menu.addSeparator()
            action = QAction(label, self)
            action.triggered.connect(callback)
            file_menu.addAction(action)

    def _build_test_case_tab(self) -> None:
        layout = QVBoxLayout(self.test_case_tab)
        self.test_case_model = QStandardItemModel()
        self.test_case_model.setHorizontalHeaderLabels(
            ["Test Case", "Step Count", "Linked Requirements", "Covered", "Source Documents"]
        )
        self.test_case_proxy = GlobalFilterProxy("explorer", self)
        self.test_case_proxy.setSourceModel(self.test_case_model)

        self.test_case_view = QTreeView()
        self.test_case_view.setModel(self.test_case_proxy)
        self.test_case_view.setSortingEnabled(True)
        self.test_case_view.setAlternatingRowColors(True)
        self.test_case_view.setRootIsDecorated(True)
        self.test_case_view.expandToDepth(0)
        self.test_case_view.selectionModel().selectionChanged.connect(self._on_test_case_selected)
        layout.addWidget(self.test_case_view)

    def _build_requirements_tab(self) -> None:
        layout = QVBoxLayout(self.requirements_tab)
        self.requirements_model = RequirementsMatrixModel(self)
        self.requirements_proxy = GlobalFilterProxy("requirements", self)
        self.requirements_proxy.setSourceModel(self.requirements_model)

        self.requirements_view = QTableView()
        self.requirements_view.setModel(self.requirements_proxy)
        self.requirements_view.setSortingEnabled(True)
        self.requirements_view.setSelectionBehavior(QTableView.SelectRows)
        self.requirements_view.setAlternatingRowColors(True)
        self.requirements_view.horizontalHeader().setStretchLastSection(True)
        self.requirements_view.selectionModel().selectionChanged.connect(self._on_requirement_selected)
        layout.addWidget(self.requirements_view)

    def _build_stakeholder_tab(self) -> None:
        layout = QVBoxLayout(self.stakeholder_tab)
        self.stakeholder_model = StakeholderOverviewModel(self)
        self.stakeholder_proxy = GlobalFilterProxy("stakeholders", self)
        self.stakeholder_proxy.setSourceModel(self.stakeholder_model)

        self.stakeholder_view = QTableView()
        self.stakeholder_view.setModel(self.stakeholder_proxy)
        self.stakeholder_view.setSortingEnabled(True)
        self.stakeholder_view.setSelectionBehavior(QTableView.SelectRows)
        self.stakeholder_view.setAlternatingRowColors(True)
        self.stakeholder_view.horizontalHeader().setStretchLastSection(True)
        self.stakeholder_view.selectionModel().selectionChanged.connect(self._on_stakeholder_selected)
        layout.addWidget(self.stakeholder_view)

    def _build_orphan_tab(self) -> None:
        layout = QVBoxLayout(self.orphan_tab)
        self.orphan_model = OrphanModel(self)
        self.orphan_proxy = GlobalFilterProxy("orphans", self)
        self.orphan_proxy.setSourceModel(self.orphan_model)

        self.orphan_view = QTableView()
        self.orphan_view.setModel(self.orphan_proxy)
        self.orphan_view.setSortingEnabled(True)
        self.orphan_view.setSelectionBehavior(QTableView.SelectRows)
        self.orphan_view.setAlternatingRowColors(True)
        self.orphan_view.horizontalHeader().setStretchLastSection(True)
        self.orphan_view.selectionModel().selectionChanged.connect(self._on_orphan_selected)
        layout.addWidget(self.orphan_view)

    def _build_summary_tab(self) -> None:
        layout = QVBoxLayout(self.summary_tab)
        panel = QFrame()
        form = QFormLayout(panel)
        self.summary_labels = {
            "total_stakeholders": QLabel("0"),
            "total_requirements": QLabel("0"),
            "covered_requirements": QLabel("0"),
            "uncovered_requirements": QLabel("0"),
            "coverage_percent": QLabel("0%"),
        }
        form.addRow("Total Stakeholder Requirements", self.summary_labels["total_stakeholders"])
        form.addRow("Total System Requirements", self.summary_labels["total_requirements"])
        form.addRow("Covered Requirements", self.summary_labels["covered_requirements"])
        form.addRow("Uncovered Requirements", self.summary_labels["uncovered_requirements"])
        form.addRow("Coverage Percentage", self.summary_labels["coverage_percent"])
        layout.addWidget(panel)
        layout.addStretch()

    def _current_filter_state(self) -> GlobalFilterState:
        return GlobalFilterState(
            stakeholder=self.filter_stakeholder.text(),
            requirement=self.filter_requirement.text(),
            test_case=self.filter_test_case.text(),
            coverage=self.filter_coverage.currentText(),
            prefix=self.filter_prefix.text(),
        )

    def _apply_global_filters(self) -> None:
        state = self._current_filter_state()
        self.requirements_proxy.set_filter_state(state)
        self.orphan_proxy.set_filter_state(state)
        self.stakeholder_proxy.set_filter_state(state)
        self.test_case_proxy.set_filter_state(state)
        self._refresh_summary()
        self._update_detail_for_current_tab()

    def _clear_global_filters(self) -> None:
        self.filter_stakeholder.clear()
        self.filter_requirement.clear()
        self.filter_test_case.clear()
        self.filter_prefix.clear()
        self.filter_coverage.setCurrentText("All")
        self._apply_global_filters()

    def _set_dirty(self, dirty: bool) -> None:
        self.dirty = dirty
        self._update_title()

    def _update_title(self) -> None:
        suffix = " *" if self.dirty else ""
        self.setWindowTitle(f"Compliance Analyzer - {self.project_manager.project_name}{suffix}")

    def handle_new_project(self) -> None:
        if not self._confirm_discard():
            return
        name, ok = QInputDialog.getText(self, "New Project", "Project name:")
        if not ok:
            return
        self.project_manager.new_project((name or "").strip() or "Untitled")
        self._reset_state()
        self._set_dirty(False)
        self.statusBar().showMessage("New project created")

    def handle_open_project(self) -> None:
        if not self._confirm_discard():
            return
        filepath, _ = QFileDialog.getOpenFileName(
            self,
            "Open Compliance Project",
            "",
            "Compliance Project (*.compliance);;All Files (*.*)",
        )
        if not filepath:
            return

        payload, _ = self.project_manager.load_project(filepath)
        self._load_from_payload(payload)
        self._set_dirty(False)
        self.statusBar().showMessage(f"Opened project {filepath}")

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
                config_requirements=sorted(self.config_requirements),
            )
        except ValueError:
            self.handle_save_project_as()
            return

        self._set_dirty(False)
        self.statusBar().showMessage(f"Saved project to {path}")

    def handle_save_project_as(self) -> None:
        filepath, _ = QFileDialog.getSaveFileName(
            self,
            "Save Compliance Project",
            "",
            "Compliance Project (*.compliance)",
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
            config_requirements=sorted(self.config_requirements),
        )
        self._set_dirty(False)
        self.statusBar().showMessage(f"Saved project to {filepath}")

    def handle_add_requirements(self) -> None:
        filepaths, _ = QFileDialog.getOpenFileNames(
            self,
            "Select Requirement Documents",
            "",
            "Word Documents (*.docx)",
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
                QMessageBox.critical(self, "Error", f"Failed to add {fp}: {exc}")

        if added:
            self._set_dirty(True)
        self._refresh_all_views()
        self.statusBar().showMessage(f"Added {added} requirement document(s)")

    def handle_add_tests(self) -> None:
        filepaths, _ = QFileDialog.getOpenFileNames(
            self,
            "Select Test Procedure Documents",
            "",
            "Word Documents (*.docx)",
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
                QMessageBox.critical(self, "Error", f"Failed to add {fp}: {exc}")

        if added:
            self._set_dirty(True)
        self._refresh_all_views()
        self.statusBar().showMessage(f"Added {added} test procedure document(s)")

    def handle_run_analysis(self) -> None:
        if not self.requirements:
            QMessageBox.warning(self, "No Requirements", "Please add requirement documents first.")
            return
        if not self.test_cases:
            QMessageBox.warning(self, "No Tests", "Please add test procedure documents first.")
            return

        self._recompute_analysis()
        self._refresh_all_views()
        self._set_dirty(True)
        self.statusBar().showMessage("Analysis complete")

    def handle_export_csv(self) -> None:
        if not self.results:
            QMessageBox.warning(self, "No Results", "Run analysis before exporting.")
            return
        filepath, _ = QFileDialog.getSaveFileName(self, "Export Analysis to CSV", "", "CSV (*.csv)")
        if not filepath:
            return
        export_analysis_csv(filepath, self.results)
        self.statusBar().showMessage(f"Exported CSV to {filepath}")

    def handle_exit(self) -> None:
        self.close()

    def closeEvent(self, event: QCloseEvent) -> None:
        if self._confirm_discard():
            self.doc_manager.cleanup()
            event.accept()
            return
        event.ignore()

    def _reset_state(self) -> None:
        self.requirements = {}
        self.test_cases = []
        self.results = []
        self.orphans = []
        self.summary = {}
        self.config_requirements = set()
        self.doc_manager.clear()
        self._refresh_all_views()

    def _load_from_payload(self, payload: dict) -> None:
        self.config_requirements = set(payload.get("config_requirements", []))
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
        self._refresh_requirements_matrix()
        self._refresh_test_case_explorer()
        self._refresh_stakeholders()
        self._refresh_orphans()
        self._apply_global_filters()

    def _refresh_requirements_matrix(self) -> None:
        rows = self.results if self.results else [
            AnalysisResult(
                req_id=req.req_id,
                stakeholder_id=req.stakeholder_id,
                source_doc=req.source_doc,
                covered=False,
                test_steps=[],
                test_cases=[],
            )
            for req in self._active_requirements()
        ]
        rows = sorted(
            rows,
            key=lambda r: (
                _norm(r.stakeholder_id or ""),
                _norm(r.req_id),
                0 if r.covered else 1,
                _norm(", ".join(r.test_steps)),
            ),
        )
        self.requirements_model.set_rows(rows)

    def _refresh_test_case_explorer(self) -> None:
        self.test_case_model.removeRows(0, self.test_case_model.rowCount())
        grouped = defaultdict(list)
        for tc in self.test_cases:
            grouped[self._test_case_label(tc)].append(tc)

        known_req_ids = {req.req_id for req in self._active_requirements()}
        for test_case_label in sorted(grouped.keys(), key=lambda value: value.lower()):
            members = grouped[test_case_label]
            req_ids = sorted({tc.ref_id for tc in members if tc.ref_id})
            stakeholder_ids = sorted(
                {
                    self.requirements[req_id].stakeholder_id
                    for req_id in req_ids
                    if req_id in self.requirements and self.requirements[req_id].stakeholder_id
                }
            )
            steps = sorted({tc.ts_id for tc in members if tc.ts_id})
            docs = sorted({tc.source_doc for tc in members if tc.source_doc})
            covered = any(req_id in known_req_ids for req_id in req_ids)
            coverage_text = "YES" if covered else "NO"

            parent_items = [
                QStandardItem(test_case_label),
                QStandardItem(str(len(steps))),
                QStandardItem(", ".join(req_ids) if req_ids else "-"),
                QStandardItem(coverage_text),
                QStandardItem(", ".join(docs) if docs else "-"),
            ]

            parent_items[0].setData(
                {
                    "stakeholder": ", ".join(stakeholder_ids),
                    "requirement": ", ".join(req_ids),
                    "test_case": test_case_label,
                    "coverage": coverage_text,
                    "prefix_values": stakeholder_ids + req_ids + steps + [test_case_label],
                    "detail": {
                        "test_case": test_case_label,
                        "stakeholders": stakeholder_ids,
                        "requirements": req_ids,
                        "steps": steps,
                        "documents": docs,
                    },
                },
                ROLE_PAYLOAD,
            )

            details = [
                ("Stakeholder IDs", ", ".join(stakeholder_ids) if stakeholder_ids else "-"),
                ("Requirement IDs", ", ".join(req_ids) if req_ids else "-"),
                ("Validation Test Steps", ", ".join(steps) if steps else "-"),
            ]
            for key, value in details:
                children = [QStandardItem(key), QStandardItem(value), QStandardItem(""), QStandardItem(""), QStandardItem("")]
                parent_items[0].appendRow(children)

            self.test_case_model.appendRow(parent_items)

        self.test_case_view.expandToDepth(0)

    def _refresh_stakeholders(self) -> None:
        if self.results:
            source_rows = self.results
        else:
            source_rows = [
                AnalysisResult(
                    req_id=req.req_id,
                    stakeholder_id=req.stakeholder_id,
                    source_doc=req.source_doc,
                    covered=False,
                    test_steps=[],
                    test_cases=[],
                )
                for req in self._active_requirements()
            ]

        by_stakeholder: Dict[str, dict] = {}
        for row in source_rows:
            stakeholder = row.stakeholder_id or "UNSPECIFIED"
            entry = by_stakeholder.setdefault(
                stakeholder,
                {
                    "stakeholder_id": stakeholder,
                    "requirements": 0,
                    "covered": 0,
                    "uncovered": 0,
                    "coverage_pct": 0.0,
                    "test_cases": set(),
                    "requirement_ids": [],
                    "test_steps": set(),
                },
            )
            entry["requirements"] += 1
            entry["covered"] += 1 if row.covered else 0
            entry["uncovered"] += 0 if row.covered else 1
            entry["requirement_ids"].append(row.req_id)
            entry["test_cases"].update(row.test_cases)
            entry["test_steps"].update(row.test_steps)

        rows = []
        for _, item in sorted(by_stakeholder.items(), key=lambda pair: pair[0].lower()):
            item["coverage_pct"] = (item["covered"] / item["requirements"] * 100.0) if item["requirements"] else 0.0
            item["test_cases"] = sorted(item["test_cases"], key=lambda x: x.lower())
            item["requirement_ids"] = sorted(set(item["requirement_ids"]), key=lambda x: x.lower())
            item["test_steps"] = sorted(item["test_steps"], key=lambda x: x.lower())
            rows.append(item)

        self.stakeholder_model.set_rows(rows)

    def _refresh_orphans(self) -> None:
        self.orphan_model.set_rows(self.orphans)

    def _refresh_summary(self) -> None:
        visible_results: List[AnalysisResult] = []
        for row in range(self.requirements_proxy.rowCount()):
            idx = self.requirements_proxy.index(row, 0)
            src = self.requirements_proxy.mapToSource(idx)
            result = self.requirements_model.row_at(src.row())
            if result:
                visible_results.append(result)

        if visible_results:
            total_requirements = len(visible_results)
            covered = sum(1 for row in visible_results if row.covered)
            uncovered = total_requirements - covered
            stakeholders = {row.stakeholder_id for row in visible_results if row.stakeholder_id}
            coverage_pct = round((covered / total_requirements) * 100.0, 2) if total_requirements else 0.0
        else:
            active_reqs = self._active_requirements()
            stakeholders = {req.stakeholder_id for req in active_reqs if req.stakeholder_id}
            total_requirements = self.summary.get("total_requirements", len(active_reqs))
            covered = self.summary.get("covered_requirements", 0)
            uncovered = self.summary.get("uncovered_requirements", 0)
            coverage_pct = self.summary.get("coverage_percent", 0)

        self.summary_labels["total_stakeholders"].setText(str(len(stakeholders)))
        self.summary_labels["total_requirements"].setText(str(total_requirements))
        self.summary_labels["covered_requirements"].setText(str(covered))
        self.summary_labels["uncovered_requirements"].setText(str(uncovered))
        self.summary_labels["coverage_percent"].setText(f"{coverage_pct}%")

    def _confirm_discard(self) -> bool:
        if not self.dirty:
            return True
        result = QMessageBox.question(
            self,
            "Unsaved Changes",
            "You have unsaved changes. Save before continuing?",
            QMessageBox.Yes | QMessageBox.No | QMessageBox.Cancel,
            QMessageBox.Yes,
        )
        if result == QMessageBox.Cancel:
            return False
        if result == QMessageBox.Yes:
            self.handle_save_project()
            return not self.dirty
        return True

    def _active_requirements(self) -> List[Requirement]:
        if not self.config_requirements:
            return list(self.requirements.values())
        return [r for r in self.requirements.values() if r.req_id not in self.config_requirements]

    def _recompute_analysis(self) -> None:
        active = self._active_requirements()
        self.results, self.orphans, self.summary = analyze(
            active,
            self.test_cases,
            excluded_req_ids=self.config_requirements,
        )

    def _test_case_label(self, tc: TestCase) -> str:
        if tc.test_case_id:
            label = f"Test Case {tc.test_case_id}"
            if tc.test_case_title:
                label += f": {tc.test_case_title}"
            return label
        return "Unassigned Test Case"

    def _open_config_requirements(self) -> None:
        dialog = QDialog(self)
        dialog.setWindowTitle("Configuration Requirements")
        dialog.resize(540, 420)
        layout = QVBoxLayout(dialog)

        info = QLabel("These requirement IDs are excluded from coverage and summary.")
        layout.addWidget(info)

        listbox = QListWidget()
        for req_id in sorted(self.config_requirements):
            listbox.addItem(req_id)
        layout.addWidget(listbox, 1)

        add_row = QHBoxLayout()
        entry = QLineEdit()
        add_btn = QPushButton("Add")
        add_row.addWidget(QLabel("Add ID"))
        add_row.addWidget(entry, 1)
        add_row.addWidget(add_btn)
        layout.addLayout(add_row)

        bulk_label = QLabel("Bulk add (comma/space/newline separated)")
        bulk_text = QPlainTextEdit()
        bulk_btn = QPushButton("Add Bulk")
        layout.addWidget(bulk_label)
        layout.addWidget(bulk_text)
        layout.addWidget(bulk_btn, 0, Qt.AlignRight)

        action_row = QHBoxLayout()
        remove_btn = QPushButton("Remove Selected")
        clear_btn = QPushButton("Clear")
        apply_btn = QPushButton("Apply")
        cancel_btn = QPushButton("Cancel")
        action_row.addWidget(remove_btn)
        action_row.addWidget(clear_btn)
        action_row.addStretch()
        action_row.addWidget(apply_btn)
        action_row.addWidget(cancel_btn)
        layout.addLayout(action_row)

        def add_single() -> None:
            val = entry.text().strip()
            if not val:
                return
            existing = {listbox.item(i).text() for i in range(listbox.count())}
            if val not in existing:
                listbox.addItem(val)
            entry.clear()

        def add_bulk() -> None:
            raw = bulk_text.toPlainText()
            parts = re.split(r"[,\s]+", raw.strip())
            existing = {listbox.item(i).text() for i in range(listbox.count())}
            for part in parts:
                if part and part not in existing:
                    listbox.addItem(part)
                    existing.add(part)
            bulk_text.clear()

        def remove_selected() -> None:
            for item in listbox.selectedItems():
                row = listbox.row(item)
                listbox.takeItem(row)

        def clear_all() -> None:
            listbox.clear()

        def apply_and_close() -> None:
            self.config_requirements = {listbox.item(i).text() for i in range(listbox.count())}
            if self.test_cases and self.requirements:
                self._recompute_analysis()
            self._refresh_all_views()
            self._set_dirty(True)
            dialog.accept()

        add_btn.clicked.connect(add_single)
        bulk_btn.clicked.connect(add_bulk)
        remove_btn.clicked.connect(remove_selected)
        clear_btn.clicked.connect(clear_all)
        apply_btn.clicked.connect(apply_and_close)
        cancel_btn.clicked.connect(dialog.reject)
        dialog.exec()

    def _on_test_case_selected(self) -> None:
        indexes = self.test_case_view.selectionModel().selectedRows()
        if not indexes:
            return
        source_index = self.test_case_proxy.mapToSource(indexes[0])
        payload = source_index.data(ROLE_PAYLOAD) or {}
        detail = payload.get("detail")
        if not detail:
            parent = source_index.parent()
            if parent.isValid():
                source_index = parent
                payload = source_index.data(ROLE_PAYLOAD) or {}
                detail = payload.get("detail")
        if not detail:
            return

        text = "\n".join(
            [
                f"Test Case: {detail['test_case']}",
                f"Stakeholder IDs: {', '.join(detail['stakeholders']) if detail['stakeholders'] else '-'}",
                f"Requirement IDs: {', '.join(detail['requirements']) if detail['requirements'] else '-'}",
                f"Validation Test Steps: {', '.join(detail['steps']) if detail['steps'] else '-'}",
                f"Source Documents: {', '.join(detail['documents']) if detail['documents'] else '-'}",
            ]
        )
        self.detail_dock.setWindowTitle("Test Case Details")
        self.detail_text.setPlainText(text)

    def _on_requirement_selected(self) -> None:
        indexes = self.requirements_view.selectionModel().selectedRows()
        if not indexes:
            return
        source = self.requirements_proxy.mapToSource(indexes[0])
        row = self.requirements_model.row_at(source.row())
        if not row:
            return

        text = "\n".join(
            [
                f"Requirement ID: {row.req_id}",
                f"Stakeholder ID: {row.stakeholder_id or '-'}",
                f"Coverage: {'YES' if row.covered else 'NO'}",
                f"Linked Test Cases: {', '.join(row.test_cases) if row.test_cases else '-'}",
                f"Step-level Validation: {', '.join(row.test_steps) if row.test_steps else '-'}",
                f"Source Document: {row.source_doc}",
            ]
        )
        self.detail_dock.setWindowTitle("Requirement Details")
        self.detail_text.setPlainText(text)

    def _on_stakeholder_selected(self) -> None:
        indexes = self.stakeholder_view.selectionModel().selectedRows()
        if not indexes:
            return
        source = self.stakeholder_proxy.mapToSource(indexes[0])
        row = self.stakeholder_model.row_at(source.row())
        if not row:
            return

        text = "\n".join(
            [
                f"Stakeholder ID: {row['stakeholder_id']}",
                f"Requirements: {row['requirements']}",
                f"Covered: {row['covered']}",
                f"Uncovered: {row['uncovered']}",
                f"Coverage %: {row['coverage_pct']:.2f}%",
                f"Requirement IDs: {', '.join(row['requirement_ids']) if row['requirement_ids'] else '-'}",
                f"Linked Test Cases: {', '.join(row['test_cases']) if row['test_cases'] else '-'}",
                f"Validation Steps: {', '.join(row['test_steps']) if row['test_steps'] else '-'}",
            ]
        )
        self.detail_dock.setWindowTitle("Stakeholder Details")
        self.detail_text.setPlainText(text)

    def _on_orphan_selected(self) -> None:
        indexes = self.orphan_view.selectionModel().selectedRows()
        if not indexes:
            return
        source = self.orphan_proxy.mapToSource(indexes[0])
        row = self.orphan_model.row_at(source.row())
        if not row:
            return

        text = "\n".join(
            [
                f"Test Step ID: {row.ts_id}",
                f"Referenced Requirement: {row.ref_id}",
                f"Test Document: {row.source_doc}",
            ]
        )
        self.detail_dock.setWindowTitle("Orphan Reference Details")
        self.detail_text.setPlainText(text)

    def _update_detail_for_current_tab(self) -> None:
        current = self.tabs.currentIndex()
        if current == 0:
            self._on_test_case_selected()
        elif current == 1:
            self._on_requirement_selected()
        elif current == 2:
            self._on_stakeholder_selected()
        elif current == 3:
            self._on_orphan_selected()
        else:
            self.detail_dock.setWindowTitle("Details")
            self.detail_text.setPlainText("Summary dashboard reflects current global filters.")


def run_app() -> None:
    app = QApplication.instance() or QApplication([])
    window = ComplianceApp()
    window.show()
    app.exec()
