"""The sdist must carry the changelog and every file the tests need (Audit #12)."""
import fnmatch
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = (ROOT / "MANIFEST.in").read_text().splitlines()


def test_changelog_is_shipped():
    assert any(line.startswith("include") and "CHANGELOG.md" in line.split() for line in MANIFEST)


def test_every_test_file_is_in_the_manifest():
    globs = [g for line in MANIFEST if line.startswith("recursive-include tests") for g in line.split()[2:]]
    for f in (ROOT / "tests").rglob("*"):
        if f.is_file() and "__pycache__" not in f.parts:
            assert any(fnmatch.fnmatch(f.name, g) for g in globs), f"{f.relative_to(ROOT)} is not shipped in the sdist"
