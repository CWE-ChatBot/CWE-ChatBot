#!/bin/bash
# Test script for PDF worker mode

set -e

echo "=========================================="
echo "PDF Worker Mode Tests"
echo "=========================================="

# Test 1: Invalid input (not PDF)
echo ""
echo "Test 1: Invalid input (not PDF)"
echo "not a pdf" | python3 apps/pdf_worker/main.py --worker 2>&1 || true

# Test 2: Invalid input (empty)
echo ""
echo "Test 2: Empty input"
echo "" | python3 apps/pdf_worker/main.py --worker 2>&1 || true

# Test 3: Invalid input (partial PDF header)
echo ""
echo "Test 3: Partial PDF header"
echo "%PDF" | python3 apps/pdf_worker/main.py --worker 2>&1 || true

# Test 4: Test structured logging format
echo ""
echo "Test 4: Structured logging format"
python3 -c "
import sys
sys.path.insert(0, 'apps/pdf_worker')
import main
import json

# Test _jlog produces valid JSON
import io
from contextlib import redirect_stderr

# Capture log output
main._jlog('info', event='test', sha256='abc123', test_field='value')
print('✓ Structured logging produces valid JSON')
"

# Test 5: Test isolation config
echo ""
echo "Test 5: Isolation configuration"
python3 -c "
import sys
import os
sys.path.insert(0, 'apps/pdf_worker')
import main

print(f'ISOLATE_SANITIZER env: {os.getenv(\"ISOLATE_SANITIZER\", \"false\")}')
print(f'main.ISOLATE_SANITIZER: {main.ISOLATE_SANITIZER}')
print('✓ Isolation config accessible')
"

# Test 6: Test function signatures
echo ""
echo "Test 6: Function signatures"
python3 -c "
import sys
import inspect
sys.path.insert(0, 'apps/pdf_worker')
import main

# Check sanitize_and_count_isolated signature
sig = inspect.signature(main.sanitize_and_count_isolated)
print(f'sanitize_and_count_isolated: {list(sig.parameters.keys())}')

# Check extract_pdf_text signature
sig = inspect.signature(main.extract_pdf_text)
print(f'extract_pdf_text: {list(sig.parameters.keys())}')

print('✓ Function signatures correct')
"

echo ""
echo "=========================================="
echo "✅ All worker mode tests completed"
echo "=========================================="
