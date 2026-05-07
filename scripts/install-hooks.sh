#!/bin/bash
set -e

echo "Installing pre-commit hooks..."
pre-commit install

echo "Running hooks against all files..."
pre-commit run --all-files

echo "Done!"
