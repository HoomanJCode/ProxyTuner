#!/usr/bin/env bash
set -euo pipefail

echo "=== ProxyTuner Publish Script ==="
echo ""

# Clean previous builds
echo "Cleaning previous builds..."
rm -rf dist/ build/ *.egg-info src/*.egg-info

# Build
echo "Building package..."
python -m build

# Check dist
echo ""
echo "Built packages:"
ls -la dist/

# Upload
echo ""
echo "Uploading to PyPI..."
twine upload dist/*

echo ""
echo "✓ Published to PyPI!"
echo "Install with: pip install proxy-tuner"
