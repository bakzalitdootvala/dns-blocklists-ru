.PHONY: check test lint validate build refresh ips

check: lint test validate
	python3 scripts/ru/check_artifact.py
	git diff --check

lint:
	.venv/bin/ruff check scripts/ru tests
	.venv/bin/ruff format --check scripts/ru tests

test:
	python3 -m unittest discover -s tests -v

validate:
	python3 scripts/ru/pipeline.py validate

refresh:
	python3 scripts/ru/sync_upstream.py
	python3 scripts/ru/pipeline.py refresh

build:
	python3 scripts/ru/pipeline.py build

ips:
	python3 scripts/ru/threat_intel.py refresh-ips
	python3 scripts/ru/threat_intel.py build-ips
