.PHONY: setup test run-mvp run-full bench-latency corpus figures clean

VENV := .venv
PYTHON := $(VENV)/bin/python
PYTEST := $(VENV)/bin/pytest

setup:
	python3 -m venv $(VENV)
	$(VENV)/bin/pip install -e .[dev]

test:
	PYTHONPATH=. $(PYTEST) -v tests/

run-mvp:
	PYTHONPATH=. $(PYTHON) eval/runner.py --corpus adaptive --mode sim

run-full:
	PYTHONPATH=. $(PYTHON) eval/runner.py --corpus all --mode sim

bench-latency:
	PYTHONPATH=. $(PYTHON) eval/latency_bench.py

corpus:
	PYTHONPATH=. $(PYTHON) tasks/generate_corpus.py

figures:
	PYTHONPATH=. $(PYTHON) eval/plot_figures.py

clean:
	rm -rf .pytest_cache results/*.jsonl results/*.sqlite figures/*.svg
