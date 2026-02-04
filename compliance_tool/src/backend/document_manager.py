import os
import shutil
from typing import List

from src.utils.logger import get_logger


class DocumentManager:
    def __init__(self, base_dir: str):
        self.base_dir = base_dir
        self.logger = get_logger(self.__class__.__name__)
        self.requirements_dir = os.path.join(base_dir, "documents", "requirements")
        self.test_dir = os.path.join(base_dir, "documents", "test_procedures")
        self._requirement_docs: List[str] = []
        self._test_docs: List[str] = []

    def add_document(self, filepath: str, doc_type: str) -> str:
        if doc_type not in ("requirements", "test_procedures"):
            raise ValueError("doc_type must be 'requirements' or 'test_procedures'")

        target_dir = self.requirements_dir if doc_type == "requirements" else self.test_dir
        os.makedirs(target_dir, exist_ok=True)
        filename = os.path.basename(filepath)
        dest_path = os.path.join(target_dir, filename)
        dest_path = self._avoid_overwrite(dest_path)

        shutil.copy2(filepath, dest_path)
        self.logger.info("Copied %s to %s", filepath, dest_path)

        if doc_type == "requirements":
            self._requirement_docs.append(dest_path)
        else:
            self._test_docs.append(dest_path)

        return dest_path

    def list_documents(self, doc_type: str) -> List[str]:
        if doc_type == "requirements":
            return list(self._requirement_docs)
        if doc_type == "test_procedures":
            return list(self._test_docs)
        raise ValueError("doc_type must be 'requirements' or 'test_procedures'")

    @staticmethod
    def _avoid_overwrite(path: str) -> str:
        if not os.path.exists(path):
            return path
        base, ext = os.path.splitext(path)
        i = 1
        while True:
            candidate = f"{base} ({i}){ext}"
            if not os.path.exists(candidate):
                return candidate
            i += 1
