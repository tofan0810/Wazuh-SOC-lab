.PHONY: test test-static health

test: test-static

test-static:
	python -m unittest discover -s tests -p "test_*.py" -v

health:
	python tests/e2e/lab_health.py
