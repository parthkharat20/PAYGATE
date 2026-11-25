.PHONY: setup test run-ci run-live replay bench-latency clean

VENV := .venv
PYTHON := $(VENV)/bin/python
PYTEST := $(VENV)/bin/pytest

setup:
	python3 -m venv $(VENV)
	$(VENV)/bin/pip install -e .[dev]

test:
	MPLCONFIGDIR=/tmp/mpl_cache PYTHONPATH=. $(PYTEST) -v tests/

run-ci:
	MPLCONFIGDIR=/tmp/mpl_cache PYTHONPATH=. $(PYTHON) scripts/run_ablation.py --ci

run-live:
	MPLCONFIGDIR=/tmp/mpl_cache PYTHONPATH=. $(PYTHON) scripts/run_ablation.py --live

replay:
	PYTHONPATH=. $(PYTHON) scripts/replay_ablation.py

bench-latency:
	PYTHONPATH=. $(PYTHON) scripts/latency_bench.py

clean:
	rm -rf .pytest_cache results/ci_mock_* /tmp/mpl_cache
