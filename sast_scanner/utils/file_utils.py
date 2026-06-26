"""File and path utilities."""
import os
import fnmatch
from pathlib import Path
from typing import List, Set, Optional, Iterator


DEFAULT_IGNORE_DIRS = {
    ".git", ".svn", ".hg", "__pycache__", "venv", ".venv", "env", "node_modules",
    "dist", "build", "target", ".tox", ".pytest_cache", ".mypy_cache", ".next",
    ".nuxt", ".parcel-cache", ".turbo", ".output", "out", "coverage", "site-packages",
}

DEFAULT_IGNORE_FILES = {
    "*.min.js", "*.min.css", "*.bundle.js", "*.map", "*.lock", "yarn.lock",
    "package-lock.json", "Pipfile.lock", "poetry.lock", "*.pyc", "*.pyo", "*.so",
    "*.dll", "*.exe", "*.bin", "*.jpg", "*.png", "*.gif", "*.mp4", "*.zip", "*.tar.gz",
}


class FileWalker:
    """Walks a target directory and yields scannable files."""

    def __init__(
        self,
        target: str,
        ignore_dirs: Optional[Set[str]] = None,
        ignore_files: Optional[Set[str]] = None,
        max_size: int = 5 * 1024 * 1024,
        include_languages: Optional[Set[str]] = None,
    ):
        self.target = Path(target).resolve()
        self.ignore_dirs = ignore_dirs or DEFAULT_IGNORE_DIRS
        self.ignore_files = ignore_files or DEFAULT_IGNORE_FILES
        self.max_size = max_size
        self.include_languages = include_languages

    def _is_ignored_dir(self, path: Path) -> bool:
        return any(part in self.ignore_dirs for part in path.parts)

    def _is_ignored_file(self, name: str) -> bool:
        return any(fnmatch.fnmatch(name, pattern) for pattern in self.ignore_files)

    def _lang_filter(self, path: Path) -> bool:
        if not self.include_languages:
            return True
        ext = path.suffix.lower()
        mapping = {
            ".py": "python", ".js": "javascript", ".jsx": "javascript", ".ts": "typescript",
            ".tsx": "typescript", ".java": "java", ".c": "c", ".cpp": "cpp", ".cc": "cpp",
            ".h": "c", ".hpp": "cpp", ".go": "go", ".php": "php", ".rb": "ruby",
            ".cs": "csharp", ".swift": "swift", ".kt": "kotlin", ".rs": "rust",
            ".html": "html", ".xml": "xml", ".json": "json", ".yaml": "yaml", ".yml": "yaml",
        }
        return mapping.get(ext, "*") in self.include_languages

    def iter_files(self) -> Iterator[Path]:
        if self.target.is_file():
            if self.target.stat().st_size <= self.max_size:
                yield self.target
            return
        for root, dirs, files in os.walk(self.target):
            root_path = Path(root)
            # Prune ignored directories in-place
            dirs[:] = [d for d in dirs if d not in self.ignore_dirs and not self._is_ignored_dir(root_path / d)]
            for file_name in files:
                if self._is_ignored_file(file_name):
                    continue
                file_path = root_path / file_name
                if self._is_ignored_dir(file_path.parent):
                    continue
                if not self._lang_filter(file_path):
                    continue
                try:
                    if file_path.stat().st_size > self.max_size:
                        continue
                except OSError:
                    continue
                yield file_path


def read_file_lines(path: Path) -> List[str]:
    """Read a file as a list of lines."""
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.readlines()
    except (OSError, UnicodeDecodeError):
        return []
