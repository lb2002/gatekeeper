import ast
from pathlib import Path

import pytest

MODAL_APP = Path(__file__).resolve().parents[1] / "modal_app"


@pytest.mark.parametrize("path", sorted(MODAL_APP.glob("*.py")), ids=lambda p: p.name)
def test_modal_app_files_parse(path):
    """The Modal apps are not imported by the other tests; a syntax error would only show up at deploy time."""
    ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
