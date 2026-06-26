.PHONY: install test scan scan-all baseline trend clean

install:
	python3 -m venv .venv
	.venv/bin/pip install -r requirements.txt

test:
	python3 -m pytest tests/ -v

scan:
	python3 -m sast_scanner vulnerable_app --formats html json sarif csv

scan-all:
	python3 -m sast_scanner vulnerable_app \
		--engines regex semantic secret taint sca iac custom \
		--formats html json sarif csv trend \
		--custom-rules rules

baseline:
	python3 -m sast_scanner vulnerable_app --create-baseline baseline.json

trend:
	python3 -m sast_scanner vulnerable_app --formats trend

compare:
	python3 compare_reports.py sast_reports/sast_report.json sast_reports/sast_report.json

clean:
	rm -rf sast_reports/ .pytest_cache/ __pycache__ .venv .sast_cache.json
	find . -type d -name __pycache__ -exec rm -rf {} +
