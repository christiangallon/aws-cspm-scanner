.PHONY: test format check docker coverage clean all

# Default target
all: format check test docker

# Run tests with coverage
test:
	pytest tests/ -v --cov=cspm --cov-report=term-missing --cov-report=html --cov-fail-under=70

# Check code formatting with ruff
format:
	ruff check cspm/ tests/
	ruff format --check cspm/ tests/

# Auto-format code
format-fix:
	ruff format cspm/ tests/

# Type checking
 type-check:
	mypy cspm/

# Build Docker image
docker:
	docker build -t aws-cspm:latest .

# Run full CI pipeline
ci: format check test docker

# Clean generated files
clean:
	rm -rf htmlcov/
	rm -rf .pytest_cache/
	rm -rf __pycache__/
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
