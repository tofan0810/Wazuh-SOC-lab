.PHONY: test test-static health sigma-compile sigma-check sigma-validate

test: test-static

test-static:
	python -m unittest discover -s tests -p "test_*.py" -v

sigma-compile:
	python scripts/sigma_compiler.py --compile

sigma-check:
	python scripts/sigma_compiler.py --check

sigma-validate:
	python scripts/sigma_compiler.py --validate

health:
	python tests/e2e/lab_health.py
