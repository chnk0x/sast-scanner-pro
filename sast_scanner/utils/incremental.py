"""Incremental scanning utilities."""
import hashlib
import json
from pathlib import Path
from typing import List, Dict, Set

from ..utils.file_utils import FileWalker


class IncrementalTracker:
    """Tracks file hashes so only changed files are rescanned."""

    def __init__(self, cache_path: str = ".sast_cache.json"):
        self.cache_path = Path(cache_path)
        self.cache: Dict[str, str] = {}
        if self.cache_path.exists():
            try:
                with open(self.cache_path, "r", encoding="utf-8") as f:
                    self.cache = json.load(f)
            except Exception:
                self.cache = {}

    def _file_hash(self, file_path: Path) -> str:
        h = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                while chunk := f.read(8192):
                    h.update(chunk)
        except OSError:
            return ""
        return h.hexdigest()

    def changed_files(self, files: List[Path]) -> List[Path]:
        changed = []
        for fp in files:
            current_hash = self._file_hash(fp)
            cached_hash = self.cache.get(str(fp))
            if cached_hash != current_hash:
                changed.append(fp)
        return changed

    def update(self, files: List[Path]):
        for fp in files:
            self.cache[str(fp)] = self._file_hash(fp)
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.cache_path, "w", encoding="utf-8") as f:
            json.dump(self.cache, f, indent=2)

    def reset(self):
        self.cache = {}
        if self.cache_path.exists():
            self.cache_path.unlink()
