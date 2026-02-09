import csv
from typing import Iterable

from src.backend.models import AnalysisResult


def export_analysis_csv(path: str, results: Iterable[AnalysisResult]) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(
            ["Requirement", "Stakeholder", "Covered", "Test Case Number", "Linked Test Cases", "Source Document"]
        )
        for res in results:
            covered = "YES" if res.covered else "NO"
            test_case_numbers = "; ".join(res.test_cases) if res.test_cases else "-"
            test_steps = ", ".join(res.test_steps) if res.test_steps else "-"
            writer.writerow(
                [res.req_id, res.stakeholder_id or "", covered, test_case_numbers, test_steps, res.source_doc]
            )
