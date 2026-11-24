.PHONY: setup test run-ablation bench-latency clean

VENV := .venv
PYTHON := $(VENV)/bin/python
PYTEST := $(VENV)/bin/pytest

setup:
	python3 -m venv $(VENV)
	$(VENV)/bin/pip install -e .[dev]

test:
	MPLCONFIGDIR=/tmp/mpl_cache PYTHONPATH=. $(PYTEST) -v tests/

run-ablation:
	MPLCONFIGDIR=/tmp/mpl_cache PYTHONPATH=. $(PYTHON) scripts/run_ablation.py --mock

bench-latency:
	PYTHONPATH=. $(PYTHON) eval/latency_bench.py

clean:
	rm -rf .pytest_cache results/raw_runs.jsonl results/ablation_summary.json /tmp/mpl_cache
