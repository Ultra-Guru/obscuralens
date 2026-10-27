"""Packaging guardrails: dependency pins that keep every CI leg green."""

from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent

PYPROJECT = (_ROOT / 'pyproject.toml').read_text(encoding='utf-8')
REQUIREMENTS = (_ROOT / 'requirements.txt').read_text(encoding='utf-8')

# reportlab 5.x declares Requires-Python >=3.9 but its __init__.py
# hard-raises ImportError on <3.10, which silently downgraded PDF report
# generation to the "library not installed" fallback on the 3.9 CI leg
# (test_reports / test_cli_console PDF failures, run 40556472016). The
# version marker below must not regress.
RL_PIN_OLD = "reportlab>=3.6.0,<5; python_version < '3.10'"
RL_PIN_NEW = "reportlab>=3.6.0; python_version >= '3.10'"


def test_reportlab_pin_present_in_pyproject():
    assert RL_PIN_OLD in PYPROJECT
    assert RL_PIN_NEW in PYPROJECT


def test_reportlab_pin_mirrored_in_requirements():
    assert RL_PIN_OLD in REQUIREMENTS
    assert RL_PIN_NEW in REQUIREMENTS
