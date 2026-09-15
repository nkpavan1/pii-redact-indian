import sys
from pathlib import Path

# Allow running the test suite against the source tree directly, without
# requiring `pip install -e .` first.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
