#!/bin/bash
# test_per_ip_rate_limit_manual.sh
# Quick manual test to verify per-IP rate limiting is working
#
# Usage: ./test_per_ip_rate_limit_manual.sh [requests_per_second] [duration_seconds]
#
# Example: ./test_per_ip_rate_limit_manual.sh 10 30
# Sends 10 requests/second for 30 seconds = 300 total requests

set -euo pipefail

# ============================================================================
# Configuration
# ============================================================================

URL="${URL:-https://cwe.crashedmind.com}"
REQUESTS_PER_SEC="${1:-6}"      # Default: 6 requests/second
DURATION_SEC="${2:-60}"          # Default: 60 seconds
TOTAL_REQUESTS=$((REQUESTS_PER_SEC * DURATION_SEC))

echo "=================================="
echo "Per-IP Rate Limit Manual Test"
echo "=================================="
echo "URL:              $URL"
echo "Rate:             $REQUESTS_PER_SEC req/sec"
echo "Duration:         $DURATION_SEC seconds"
echo "Total requests:   $TOTAL_REQUESTS"
echo "Rate limit:       300 req/min (5 req/sec)"
echo "Expected result:  429 errors after ~300 requests"
echo "=================================="
echo ""

# ============================================================================
# Run Test
# ============================================================================

success_count=0
rate_limited_count=0
error_count=0
first_429=""

echo "Sending requests..."
echo ""

for ((i=1; i<=TOTAL_REQUESTS; i++)); do
    # Make request and capture status code
    status=$(curl -s -o /dev/null -w "%{http_code}" "$URL" 2>/dev/null || echo "ERR")

    case "$status" in
        200|201|204|401|403|404)
            ((success_count++))
            ;;
        429)
            ((rate_limited_count++))
            if [ -z "$first_429" ]; then
                first_429="$i"
                echo "⚠️  First 429 at request $i"
            fi
            ;;
        *)
            ((error_count++))
            echo "❌ Error at request $i: $status"
            ;;
    esac

    # Progress indicator every 50 requests
    if [ $((i % 50)) -eq 0 ]; then
        echo "Progress: $i/$TOTAL_REQUESTS (✅ $success_count | ⚠️  $rate_limited_count | ❌ $error_count)"
    fi

    # Sleep to maintain request rate
    sleep $(echo "scale=3; 1.0 / $REQUESTS_PER_SEC" | bc)
done

# ============================================================================
# Results
# ============================================================================

echo ""
echo "=================================="
echo "Test Results"
echo "=================================="
echo "Total requests:   $TOTAL_REQUESTS"
echo "Successful:       $success_count"
echo "Rate limited:     $rate_limited_count"
echo "Errors:           $error_count"
echo ""

if [ -n "$first_429" ]; then
    echo "✅ Rate limiting working!"
    echo "   First 429 at request: $first_429"
    echo "   Expected around:      300"

    if [ "$first_429" -ge 250 ] && [ "$first_429" -le 350 ]; then
        echo "   Status: ✅ Within expected range"
    else
        echo "   Status: ⚠️  Outside expected range (may need tuning)"
    fi
else
    echo "❌ No rate limiting detected"
    echo "   Possible issues:"
    echo "   - Cloud Armor rule not active"
    echo "   - Rate limit threshold too high"
    echo "   - Test rate too low to trigger limit"
fi

echo ""
echo "=================================="
