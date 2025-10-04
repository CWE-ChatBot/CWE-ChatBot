# Database Operations Runbook

**Instance**: `cwe-postgres-prod`
**Project**: `cwechatbot`
**Region**: `us-central1`
**Last Updated**: 2025-10-04

## Overview

This runbook provides operational procedures for the CWE ChatBot production PostgreSQL database.

## Quick Reference

### Database Connection Details
```
Instance:     cwe-postgres-prod
Host:         10.43.0.3 (Private IP)
Port:         5432
Database:     postgres
User:         app_user (runtime), cwe-postgres-sa@cwechatbot.iam (ingestion)
Auth:         Password (app), IAM (ingestion)
```

### Key Metrics
- **Target Query Latency**: <200ms (local), <500ms p95 (production)
- **Current Performance**: 172ms avg DB query time
- **Index**: HNSW on halfvec(3072) with ef_search=32
- **Pool Size**: 4 connections, no overflow, 30min recycle
- **Availability**: ZONAL (single zone, no HA)

### High Availability Decision
**Current**: ZONAL (single-zone, no automatic failover)

**Why HA (REGIONAL) is NOT enabled:**
- **Cost**: HA doubles instance costs (~2x compute + storage + cross-zone egress)
- **Use Case**: Read-only CWE queries with static data (not mission-critical transactions)
- **Recovery**: Point-in-time recovery (PITR) provides adequate disaster recovery
- **Acceptable Downtime**: Manual failover acceptable for non-critical service
- **Data Safety**: Daily backups + 7-day PITR sufficient for data protection

**When to reconsider HA:**
- Service becomes business-critical with SLA requirements
- Handling financial transactions or user-generated data
- Cannot tolerate 15-30 minute recovery time
- Cost increase justified by business value

## Common Operations

### 1. Check Database Health

```bash
# Check instance status
gcloud sql instances describe cwe-postgres-prod \
  --project=cwechatbot \
  --format='value(state,settings.tier,settings.dataDiskSizeGb)'

# Check current connections
gcloud sql operations list \
  --instance=cwe-postgres-prod \
  --project=cwechatbot \
  --limit=5
```

### 2. Monitor Query Performance

```bash
# View slow queries (>1000ms) in Cloud Logging
gcloud logging read \
  'resource.type="cloudsql_database" AND
   resource.labels.database_id="cwechatbot:cwe-postgres-prod" AND
   jsonPayload.message=~"duration: [0-9]{4,}" AND
   severity>=WARNING' \
  --limit=50 \
  --format=json \
  --project=cwechatbot

# Check active queries via psql
gcloud sql connect cwe-postgres-prod \
  --user=app_user \
  --database=postgres \
  --project=cwechatbot

# Then in psql:
SELECT pid, age(clock_timestamp(), query_start), usename, query
FROM pg_stat_activity
WHERE state != 'idle'
  AND query NOT ILIKE '%pg_stat_activity%'
ORDER BY query_start DESC;
```

### 3. Verify Data Integrity

```bash
# Connect to database
gcloud sql connect cwe-postgres-prod \
  --user=app_user \
  --database=postgres \
  --project=cwechatbot

# Check CWE data counts
SELECT COUNT(*) as total_chunks FROM cwe_chunks;
-- Expected: 7913 chunks (969 CWEs)

# Verify HNSW index
SELECT
  schemaname,
  tablename,
  indexname,
  indexdef
FROM pg_indexes
WHERE tablename = 'cwe_chunks';

# Check table statistics
SELECT
  schemaname,
  tablename,
  n_live_tup as row_count,
  n_dead_tup as dead_rows,
  last_vacuum,
  last_autovacuum,
  last_analyze,
  last_autoanalyze
FROM pg_stat_user_tables
WHERE tablename = 'cwe_chunks';
```

### 4. Password Rotation

```bash
# Generate new password
NEWPWD=$(openssl rand -base64 32)

# Update password in Cloud SQL
gcloud sql users set-password app_user \
  --instance=cwe-postgres-prod \
  --password="$NEWPWD" \
  --project=cwechatbot

# Update Secret Manager
printf '%s' "$NEWPWD" | gcloud secrets versions add db-password-app-user \
  --data-file=- \
  --project=cwechatbot

# Restart Cloud Run service to pick up new secret
gcloud run services update cwe-chatbot \
  --region=us-central1 \
  --project=cwechatbot

# Verify connection works
# (Check Cloud Run logs for successful startup)
```

### 5. Backup and Restore

#### Manual Backup
```bash
# Create on-demand backup
gcloud sql backups create \
  --instance=cwe-postgres-prod \
  --description="Manual backup before maintenance" \
  --project=cwechatbot

# List backups
gcloud sql backups list \
  --instance=cwe-postgres-prod \
  --project=cwechatbot
```

#### Restore from Backup
```bash
# List available backups with IDs
gcloud sql backups list \
  --instance=cwe-postgres-prod \
  --project=cwechatbot \
  --format='table(id,windowStartTime,type,status)'

# Restore from specific backup ID
gcloud sql backups restore BACKUP_ID \
  --backup-instance=cwe-postgres-prod \
  --backup-project=cwechatbot \
  --instance=cwe-postgres-prod \
  --project=cwechatbot

# WARNING: This will restart the instance and cause downtime
```

#### Point-in-Time Recovery
```bash
# Restore to specific timestamp
gcloud sql backups restore \
  --instance=cwe-postgres-prod \
  --backup-instance=cwe-postgres-prod \
  --point-in-time=2025-10-04T15:30:00Z \
  --project=cwechatbot

# Clone to new instance for testing
gcloud sql instances clone cwe-postgres-prod cwe-postgres-test \
  --point-in-time=2025-10-04T15:30:00Z \
  --project=cwechatbot
```

### 6. Performance Tuning

#### Analyze Table Statistics
```bash
# Connect to database
gcloud sql connect cwe-postgres-prod --user=app_user --database=postgres --project=cwechatbot

# Run ANALYZE to update statistics
ANALYZE cwe_chunks;

# Check index usage
SELECT
  schemaname,
  tablename,
  indexname,
  idx_scan as index_scans,
  idx_tup_read as tuples_read,
  idx_tup_fetch as tuples_fetched
FROM pg_stat_user_indexes
WHERE tablename = 'cwe_chunks';
```

#### Vacuum and Maintenance
```bash
# Manual VACUUM (in psql)
VACUUM ANALYZE cwe_chunks;

# Check bloat
SELECT
  schemaname,
  tablename,
  pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) as size
FROM pg_tables
WHERE tablename = 'cwe_chunks';
```

## Troubleshooting

### Issue: High Query Latency (>500ms)

**Symptoms**: Slow response times, user complaints

**Diagnosis**:
```bash
# Check slow query logs
gcloud logging read \
  'resource.type="cloudsql_database" AND
   jsonPayload.message=~"duration:"' \
  --limit=20 \
  --project=cwechatbot

# Check CPU/Memory usage
gcloud sql instances describe cwe-postgres-prod \
  --project=cwechatbot \
  --format='json(settings.tier,diskEncryptionStatus)'
```

**Resolution**:
1. Check if HNSW index exists: `\d cwe_chunks` in psql
2. Verify `ef_search` parameter (should be 32)
3. Check connection pool isn't exhausted
4. Review instance tier - may need upgrade from db-f1-micro
5. Check for table bloat - run VACUUM ANALYZE

### Issue: Connection Pool Exhausted

**Symptoms**: "connection pool is full" errors

**Diagnosis**:
```bash
# Check active connections
SELECT count(*) FROM pg_stat_activity WHERE state = 'active';

# Check connection sources
SELECT
  usename,
  application_name,
  client_addr,
  state,
  count(*)
FROM pg_stat_activity
GROUP BY usename, application_name, client_addr, state;
```

**Resolution**:
1. Check Cloud Run instances count (max 4 connections configured)
2. Look for connection leaks in application logs
3. Verify `DB_POOL_RECYCLE_SEC=1800` is set
4. Consider increasing pool size if legitimate load

### Issue: IAM Authentication Failures

**Symptoms**: "role does not exist", "password authentication failed"

**Diagnosis**:
```bash
# Check IAM service account exists
gcloud iam service-accounts describe cwe-postgres-sa@cwechatbot.iam \
  --project=cwechatbot

# Check database user exists
gcloud sql users list \
  --instance=cwe-postgres-prod \
  --project=cwechatbot
```

**Resolution**:
1. Verify IAM user exists in Cloud SQL: `gcloud sql users list`
2. Check IAM permissions: cloudsql.instances.connect
3. For ingestion: Use IAM auth (`cwe-postgres-sa@cwechatbot.iam`)
4. For application: Use password auth (`app_user`) for performance

### Issue: Permission Denied on Tables

**Symptoms**: "permission denied for table cwe_chunks"

**Diagnosis**:
```bash
# Check table ownership (in psql)
SELECT tablename, tableowner FROM pg_tables WHERE tablename = 'cwe_chunks';

# Should show: tableowner = 'app_user'
```

**Resolution**:
```sql
-- If ownership is wrong, transfer to app_user
ALTER TABLE cwe_chunks OWNER TO app_user;

-- Grant ingestion service INSERT permission
GRANT INSERT, UPDATE, DELETE, TRUNCATE ON cwe_chunks
  TO "cwe-postgres-sa@cwechatbot.iam";
```

### Issue: Out of Memory

**Symptoms**: Instance restarts, OOM errors in logs

**Diagnosis**:
```bash
# Check memory metrics
gcloud monitoring time-series list \
  --filter='metric.type="cloudsql.googleapis.com/database/memory/utilization" AND
            resource.labels.database_id="cwechatbot:cwe-postgres-prod"' \
  --project=cwechatbot
```

**Resolution**:
1. Current tier: db-f1-micro (614 MB RAM) - very small
2. Consider upgrade to db-custom-1-3840 (3.75 GB RAM)
3. Check for query memory leaks
4. Review connection pool size

## Monitoring and Alerts

### Configured Alert Policies

1. **High CPU Usage**
   - Threshold: >80% for 5 minutes
   - Action: Investigate queries, consider tier upgrade

2. **High Memory Usage**
   - Threshold: >90% for 5 minutes
   - Action: Check connection count, review query plans

### Viewing Alerts
```bash
# List active incidents
gcloud alpha monitoring policies list --project=cwechatbot

# View specific policy
gcloud alpha monitoring policies describe POLICY_ID --project=cwechatbot
```

### Setting Up Notification Channels

Currently alerts are configured but **no notification channels** are set up.

**To add email notifications**:
```bash
# Create email notification channel
gcloud alpha monitoring channels create \
  --display-name="Database Admin Email" \
  --type=email \
  --channel-labels=email_address=admin@example.com \
  --project=cwechatbot

# Get channel ID
CHANNEL_ID=$(gcloud alpha monitoring channels list \
  --filter="displayName='Database Admin Email'" \
  --format="value(name)" \
  --project=cwechatbot)

# Update alert policy to use channel
gcloud alpha monitoring policies update POLICY_ID \
  --notification-channels=$CHANNEL_ID \
  --project=cwechatbot
```

## Backup Configuration

### Current Settings
- **Enabled**: Yes
- **Schedule**: Daily at 02:00 UTC
- **Retention**: 7 backups (7 days)
- **Point-in-Time Recovery**: Enabled (7 days of transaction logs)

### Backup Verification
```bash
# Verify backups are running
gcloud sql backups list \
  --instance=cwe-postgres-prod \
  --project=cwechatbot \
  --limit=7 \
  --format='table(id,windowStartTime,type,status)'

# Should see daily backups with status=SUCCESSFUL
```

## Maintenance Windows

**Automatic Maintenance**: Enabled (Google-managed updates)

**To schedule maintenance**:
```bash
# Set maintenance window (example: Sundays 02:00-06:00 UTC)
gcloud sql instances patch cwe-postgres-prod \
  --maintenance-window-day=SUN \
  --maintenance-window-hour=2 \
  --project=cwechatbot
```

## Disaster Recovery

### Recovery Time Objective (RTO)
- **Target**: <1 hour
- **Restore from backup**: ~15-30 minutes
- **Point-in-time recovery**: ~30-60 minutes

### Recovery Point Objective (RPO)
- **Target**: <1 hour
- **With PITR enabled**: Up to last committed transaction (few seconds)
- **Without PITR**: Last daily backup (up to 24 hours)

### DR Procedure

1. **Identify Issue**: Check Cloud Logging, monitoring dashboards
2. **Assess Data Loss**: Determine point of corruption/failure
3. **Create Clone**: Test restore on cloned instance first
4. **Verify Data**: Check row counts, run integrity queries
5. **Update DNS/Routing**: Point application to restored instance
6. **Monitor**: Watch for cascading failures

### DR Testing Schedule
- **Quarterly**: Full backup restore test
- **Monthly**: Verify backups are successful
- **Weekly**: Check monitoring alerts are working

## Performance Baselines

### Query Performance
- **Baseline (before optimization)**: 602ms avg
- **After connection pooling**: 415ms avg
- **After HNSW index**: 180ms avg
- **After transaction hints**: 172ms avg
- **Target**: <200ms local, <500ms p95 production

### Database Size
- **CWE Chunks**: 7,913 rows (969 CWEs)
- **Table Size**: ~65 MB (with indexes)
- **Expected Growth**: Minimal (CWE corpus updates quarterly)

## Security

### Authentication Model (Hybrid)
- **Application Runtime**: Password auth via `app_user`
  - **Why**: Cloud Run's connection churn (scale-to-zero, autoscaling, bursty traffic)
  - **Overhead avoided**: IAM adds ~100-300ms **per new connection**, not per query
  - With pooled connections IAM is fine, but Cloud Run creates new connections frequently
- **Data Ingestion**: IAM auth via `cwe-postgres-sa@cwechatbot.iam`
  - **Why**: Batch operation with stable connections, latency acceptable
  - **Benefit**: No password management, better audit trail

### Network Security
- **Public IP**: Disabled
- **Private IP**: 10.43.0.3 (VPC only)
- **SSL/TLS**: Required (`DB_SSLMODE=require`)
- **Firewall**: VPC firewall rules (authorized networks)

### Access Control
```sql
-- Current ownership model
cwe_chunks owned by: app_user
Permissions for ingestion: GRANT INSERT, UPDATE, DELETE, TRUNCATE
```

### Password Security
- **Storage**: Google Secret Manager (`db-password-app-user`)
- **Rotation**: Manual (recommended: quarterly)
- **Complexity**: 32-character base64-encoded
- **Access**: Cloud Run service account only

## Useful Queries

### Index Health
```sql
-- Check index size and usage
SELECT
  schemaname,
  tablename,
  indexname,
  pg_size_pretty(pg_relation_size(indexrelid)) as index_size,
  idx_scan as times_used
FROM pg_stat_user_indexes
WHERE schemaname = 'public'
ORDER BY pg_relation_size(indexrelid) DESC;
```

### Connection Pool Status
```sql
-- Active connections by state
SELECT
  state,
  count(*) as connections,
  max(age(clock_timestamp(), query_start)) as oldest_query
FROM pg_stat_activity
WHERE datname = 'postgres'
GROUP BY state;
```

### Table Bloat Check
```sql
-- Estimate table bloat
SELECT
  schemaname,
  tablename,
  pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) as total_size,
  pg_size_pretty(pg_relation_size(schemaname||'.'||tablename)) as table_size,
  pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename) -
                 pg_relation_size(schemaname||'.'||tablename)) as indexes_size,
  n_dead_tup as dead_tuples,
  round(100 * n_dead_tup / NULLIF(n_live_tup + n_dead_tup, 0), 2) as dead_pct
FROM pg_stat_user_tables
WHERE schemaname = 'public';
```

## Contact Information

**Project**: cwechatbot
**Owner**: [Your team/contact]
**On-Call**: [Escalation procedure]
**Documentation**: `/home/chris/work/CyberSecAI/cwe_chatbot_bmad/docs/`

## Revision History

| Date | Version | Changes | Author |
|------|---------|---------|--------|
| 2025-10-04 | 1.0 | Initial runbook creation | Claude |
