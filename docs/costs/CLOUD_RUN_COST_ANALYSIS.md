# Cloud Run Cost Analysis Report

**Generated**: 2025-10-23
**Service**: cwe-chatbot
**Region**: us-central1

## Executive Summary

Current monthly cost: **~$70-75/month** for minimal traffic
Primary cost driver: **Always-allocated CPU** (minScale=1 + cpu-throttling disabled)
Potential savings: **60-80%** with configuration optimization

## Current Configuration

### Compute Resources (Biggest Cost Driver)
- **CPU**: 1 vCPU allocated per instance
- **Memory**: 512 MiB per instance
- **CPU Throttling**: **DISABLED** (`cpu-throttling: false`)
  - CPU is **always allocated**, even when idle
  - Continuous billing for 1 vCPU 24/7 per instance

### Instance Scaling (Second Biggest Cost)
- **Minimum Instances**: **1** (`minScale: 1`)
  - Always 1 instance running 24/7
  - **Continuous billing** even with zero traffic
- **Maximum Instances**: 10 (`maxScale: 10`)
- **Container Concurrency**: 80 requests per instance

### Execution Environment
- **Generation**: gen2 (slightly more expensive but better performance)
- **Startup CPU Boost**: Enabled (temporary extra CPU during cold starts)
- **Request Timeout**: 300 seconds (5 minutes)

### Network Configuration
- **VPC Connector**: `run-us-central1` (egress charges for private traffic)
- **Cloud SQL Connection**: `cwechatbot:us-central1:cwe-postgres-prod`
- **Ingress**: Internal and Cloud Load Balancing

## Monthly Cost Breakdown

### Base Cost (minScale=1, always running)

```
CPU Cost:
- 1 vCPU × 730 hours × $0.00002400/vCPU-second
- ≈ $63/month (always-allocated CPU)

Memory Cost:
- 512 MiB × 730 hours × $0.00000250/GiB-second
- ≈ $1/month

Network:
- VPC Connector: ~$8-10/month (always running)
- Egress to Cloud SQL: Variable (depends on traffic)

Total Base Cost: ~$72-74/month (with minimal traffic)
```

### Cost Analysis

**Why This Configuration Is Expensive**:
1. **minScale=1**: Instance always running = continuous billing
2. **cpu-throttling=false**: CPU always allocated = premium pricing
3. **startup-cpu-boost=true**: Faster cold starts but higher cost

**This is configured for production availability**:
- ✅ Always ready (no cold starts)
- ✅ Always fast (CPU always allocated)
- ✅ Instant response times
- ❌ Expensive for low-traffic applications

## Traffic Analysis (Last 7 Days)

**Observed Activity**:
- Active WebSocket traffic (Chainlit UI polling)
- Socket.io connections every 25-30 seconds
- User sessions with file uploads and translations
- Consistent low-volume interactive usage

**Usage Pattern**: Development/testing with occasional interactive sessions

## Cost Optimization Recommendations

### Option 1: Aggressive Cost Reduction (60-80% savings)

**Target Monthly Cost**: ~$15-20/month

```bash
gcloud run services update cwe-chatbot \
  --region=us-central1 \
  --cpu-throttling \
  --min-instances=0 \
  --memory=256Mi
```

**Savings Breakdown**:
- Enable CPU throttling: **~$50/month savings**
- Set minScale=0: **~$15-20/month savings**
- Reduce memory to 256Mi: **~$0.50/month savings**

**Trade-offs**:
- ❌ 5-15 second cold start on first request after idle
- ❌ Slightly slower response times under load
- ✅ 60-80% cost reduction

### Option 2: Balanced Approach (40-50% savings)

**Target Monthly Cost**: ~$35-40/month

```bash
gcloud run services update cwe-chatbot \
  --region=us-central1 \
  --cpu-throttling
```

**Savings**:
- Enable CPU throttling only: **~$50/month savings**
- Keep minScale=1 for instant availability

**Trade-offs**:
- ✅ No cold starts (always ready)
- ❌ Slightly slower response times (CPU allocated on-demand)
- ✅ 40-50% cost reduction

### Option 3: Keep Current (Production Ready)

**Monthly Cost**: ~$70-75/month

**Best For**:
- Production environment with paying customers
- SLA requirements for instant response times
- Zero tolerance for cold starts
- Business-critical availability

## Configuration Comparison

| Configuration | Monthly Cost | Cold Start | Response Time | Best For |
|--------------|--------------|------------|---------------|----------|
| **Current (Production)** | ~$70-75 | None | Instant | Production |
| **Balanced** | ~$35-40 | None | Fast | Staging |
| **Optimized** | ~$15-20 | 5-15s | Normal | Development |

## Additional Cost Factors

### Cloud SQL Connection
- Direct connection via Cloud SQL Proxy (included in Cloud Run)
- No additional Cloud SQL Proxy charges
- Cloud SQL instance costs are separate (not analyzed here)

### VPC Connector
- Always-running connector: ~$8-10/month
- Required for private Cloud SQL access
- Egress charges apply for traffic volume

### Secret Manager
- 7 secrets in use (API keys, OAuth credentials, passwords)
- Secret access charges: negligible for current volume
- Storage: $0.06 per secret version per month

## Recommendations

### For Development/Testing Environment
**Implement Option 1 (Aggressive Optimization)**:
- Save 60-80% on Cloud Run costs
- Accept cold starts for development workflow
- Monitor for any impact on development productivity

### For Staging Environment
**Implement Option 2 (Balanced Approach)**:
- Save 40-50% while maintaining availability
- No cold starts for integration testing
- Good balance of cost and performance

### For Production Environment
**Keep Current Configuration**:
- Maintain instant response times
- Zero cold starts for end users
- Consider optimizing only if traffic remains consistently low

## Monitoring & Next Steps

### Set Up Cost Alerts
```bash
# Create budget alert for Cloud Run
gcloud billing budgets create \
  --billing-account=<YOUR_BILLING_ACCOUNT> \
  --display-name="Cloud Run cwe-chatbot Budget" \
  --budget-amount=100 \
  --threshold-rule=percent=80
```

### Monitor Usage Metrics
```bash
# Check request count (last 7 days)
gcloud logging read 'resource.type="cloud_run_revision" AND resource.labels.service_name="cwe-chatbot"' \
  --limit=1000 --freshness=7d --format="value(timestamp)" | wc -l

# Check instance utilization
gcloud monitoring time-series list \
  --filter='metric.type="run.googleapis.com/container/instance_count" AND resource.labels.service_name="cwe-chatbot"' \
  --format=table
```

### Review in 30 Days
1. Analyze actual traffic patterns
2. Measure cost savings from any changes
3. Adjust configuration based on real usage
4. Consider graduated approach (dev → staging → production)

## Implementation Commands

### To Implement Aggressive Optimization
```bash
# Back up current configuration
gcloud run services describe cwe-chatbot --region=us-central1 > docs/cloud-run-config-backup-$(date +%Y%m%d).yaml

# Apply optimizations
gcloud run services update cwe-chatbot \
  --region=us-central1 \
  --cpu-throttling \
  --min-instances=0 \
  --memory=256Mi

# Verify changes
gcloud run services describe cwe-chatbot --region=us-central1 --format=yaml
```

### To Rollback Changes
```bash
# Restore original configuration
gcloud run services update cwe-chatbot \
  --region=us-central1 \
  --no-cpu-throttling \
  --min-instances=1 \
  --memory=512Mi
```

## Conclusion

Your Cloud Run service is configured for **production-grade availability** but is being used as a **development/testing environment**. This mismatch creates an opportunity for significant cost savings.

**Recommended Action**: Implement Option 1 (Aggressive Optimization) to reduce costs by 60-80% while maintaining acceptable performance for development workflows.

**Expected Outcome**: Monthly Cloud Run costs reduced from ~$70-75 to ~$15-20 with minimal impact on development productivity.
