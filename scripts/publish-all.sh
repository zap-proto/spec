#!/bin/bash
set -e

echo "=== Publishing ZAP packages for discoverability ==="
echo ""

cd "$(dirname "$0")/.."

# 1. Publish main Rust crate first (zap-schema)
echo ">>> Publishing zap-schema to crates.io..."
cargo publish --dry-run
echo "Run 'cargo publish' to publish zap-schema"
echo ""

# 2. Publish Rust alias crates
echo ">>> Publishing zap-proto to crates.io..."
cd reserve/zap-proto
cargo publish --dry-run
echo "Run 'cd reserve/zap-proto && cargo publish' to publish"
cd ../..
echo ""

echo ">>> Publishing zap-protocol to crates.io..."
cd reserve/zap-protocol
cargo publish --dry-run
echo "Run 'cd reserve/zap-protocol && cargo publish' to publish"
cd ../..
echo ""

# 3. Publish main Python package (zap-schema)
echo ">>> Publishing zap-schema to PyPI..."
cd python
uv build
echo "Run 'cd python && uv publish' to publish zap-schema"
cd ..
echo ""

# 4. Publish Python alias packages
echo ">>> Publishing zap-proto to PyPI..."
cd reserve/zap-proto-py
python -m build 2>/dev/null || pip install build && python -m build
echo "Run 'cd reserve/zap-proto-py && twine upload dist/*' to publish"
cd ../..
echo ""

echo ">>> Publishing zap-protocol to PyPI..."
cd reserve/zap-protocol-py
python -m build 2>/dev/null || pip install build && python -m build
echo "Run 'cd reserve/zap-protocol-py && twine upload dist/*' to publish"
cd ../..
echo ""

echo "=== Summary ==="
echo ""
echo "Packages to publish:"
echo ""
echo "crates.io:"
echo "  1. cargo publish                              # zap-schema (main)"
echo "  2. cd reserve/zap-proto && cargo publish      # zap-proto (alias)"
echo "  3. cd reserve/zap-protocol && cargo publish   # zap-protocol (alias)"
echo ""
echo "PyPI:"
echo "  1. cd python && uv publish                    # zap-schema (main)"
echo "  2. cd reserve/zap-proto-py && twine upload dist/*    # zap-proto (alias)"
echo "  3. cd reserve/zap-protocol-py && twine upload dist/* # zap-protocol (alias)"
echo ""
echo "npm:"
echo "  Already configured as @zap-protocol/zapc and @zap-protocol/zap"
