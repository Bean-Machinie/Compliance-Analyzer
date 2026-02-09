import json
import os
from typing import Dict, List, Optional, Tuple

from src.backend.models import AnalysisResult, OrphanReference, Requirement, TestCase


class ProjectManager:
    def __init__(self, base_dir: str):
        self.base_dir = base_dir
        self.project_name: str = "Untitled"
        self.project_path: Optional[str] = None

    def new_project(self, name: str) -> None:
        self.project_name = name or "Untitled"
        self.project_path = None

    def save_project(
        self,
        path: Optional[str],
        requirement_docs: List[str],
        test_docs: List[str],
        requirements: List[Requirement],
        test_cases: List[TestCase],
        results: List[AnalysisResult],
        orphans: List[OrphanReference],
        summary: Dict[str, float],
    ) -> str:
        if path is None:
            if self.project_path is None:
                raise ValueError("No project path provided")
            path = self.project_path

        payload = self._build_payload(
            requirement_docs,
            test_docs,
            requirements,
            test_cases,
            results,
            orphans,
            summary,
        )

        with open(path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)

        self.project_path = path
        return path

    def load_project(self, path: str) -> Tuple[dict, dict]:
        with open(path, "r", encoding="utf-8") as f:
            payload = json.load(f)

        self.project_name = payload.get("project_name", "Untitled")
        self.project_path = path
        return payload, {
            "project_name": self.project_name,
            "project_path": self.project_path,
        }

    def _build_payload(
        self,
        requirement_docs: List[str],
        test_docs: List[str],
        requirements: List[Requirement],
        test_cases: List[TestCase],
        results: List[AnalysisResult],
        orphans: List[OrphanReference],
        summary: Dict[str, float],
    ) -> dict:
        return {
            "project_name": self.project_name,
            "requirement_documents": [self._to_rel(p) for p in requirement_docs],
            "test_documents": [self._to_rel(p) for p in test_docs],
            "requirements": [
                {
                    "id": r.req_id,
                    "stakeholder": r.stakeholder_id,
                    "source_document": self._to_rel(r.source_doc),
                }
                for r in requirements
            ],
            "test_cases": [
                {
                    "test_id": tc.ts_id,
                    "requirement_id": tc.ref_id,
                    "source_document": self._to_rel(tc.source_doc),
                    "test_case_id": tc.test_case_id,
                    "test_case_title": tc.test_case_title,
                }
                for tc in test_cases
            ],
            "analysis": {
                r.req_id: {
                    "covered": r.covered,
                    "test_cases": r.test_steps,
                    "test_case_numbers": r.test_cases,
                    "stakeholder": r.stakeholder_id,
                    "source_document": self._to_rel(r.source_doc),
                }
                for r in results
            },
            "orphan_references": [
                {
                    "test_id": o.ts_id,
                    "requirement_id": o.ref_id,
                    "source_document": self._to_rel(o.source_doc),
                }
                for o in orphans
            ],
            "summary": summary,
        }

    def _to_rel(self, path: str) -> str:
        if not path:
            return ""
        try:
            rel = os.path.relpath(path, self.base_dir)
            if not rel.startswith("..") and not os.path.isabs(rel):
                return rel.replace("\\", "/")
        except ValueError:
            pass
        return path.replace("\\", "/")

    def resolve_path(self, path: str) -> str:
        if not path:
            return path
        if os.path.isabs(path):
            return path
        return os.path.normpath(os.path.join(self.base_dir, path))
