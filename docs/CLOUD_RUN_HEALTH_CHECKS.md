# Cloud Run Health Checks - Technical Documentation

## Summary

Cloud Run **does not use Docker HEALTHCHECK directives**. It uses its own Kubernetes-based health check system with startup, liveness, and readiness probes.

## What We Removed (2025-10-08)

### Files Deleted
- `apps/chatbot/healthcheck.py` - Python health check script (unused by Cloud Run)

### Dockerfile Changes
- Removed `HEALTHCHECK` directive (ignored by Cloud Run)
- Removed `COPY healthcheck.py` line
- Removed `chmod +x /app/healthcheck.py` line

## What Cloud Run Actually Uses

### Current Configuration

**Startup Probe** (automatically configured):
```yaml
startupProbe:
  failureThreshold: 1
  periodSeconds: 240
  tcpSocket:
    port: 8080
  timeoutSeconds: 240
```

This is a simple **TCP socket check** - Cloud Run verifies that port 8080 accepts connections. That's it.

### Why This Is Sufficient for Chainlit

Chainlit is a web application that either:
1. ✅ Starts successfully and listens on port 8080
2. ❌ Fails to start (connection refused)

There's no middle ground where the app is "partially healthy" - it's either serving HTTP or it's not. The TCP probe correctly detects both states.

## Why Docker HEALTHCHECK Was Ignored

**Key Point**: Cloud Run uses container orchestration (Google Kubernetes Engine under the hood) which has its own health check system. Docker's HEALTHCHECK is a Docker-specific feature that only works when running containers with `docker run` or `docker-compose`.

**Container Platforms That Ignore Docker HEALTHCHECK**:
- ✅ Cloud Run (uses Kubernetes probes)
- ✅ Google Kubernetes Engine / GKE (uses Kubernetes probes)
- ✅ Amazon ECS (uses its own health checks)
- ✅ Azure Container Instances (uses its own health checks)

**Where Docker HEALTHCHECK Actually Works**:
- ❌ `docker run` (standalone containers)
- ❌ `docker-compose` (local development)
- ❌ Docker Swarm (legacy orchestration)

## Available Cloud Run Health Check Options

If we ever need more sophisticated health checking, Cloud Run supports:

### 1. HTTP Liveness Probe
Periodically checks an HTTP endpoint to see if the container is alive:
```yaml
livenessProbe:
  httpGet:
    path: /health
    port: 8080
  initialDelaySeconds: 10
  periodSeconds: 30
```

### 2. HTTP Readiness Probe
Checks if the container is ready to receive traffic:
```yaml
readinessProbe:
  httpGet:
    path: /ready
    port: 8080
  initialDelaySeconds: 5
  periodSeconds: 10
```

### 3. TCP Startup Probe (what we use)
Checks if the container has started and is listening:
```yaml
startupProbe:
  tcpSocket:
    port: 8080
  periodSeconds: 240
  timeoutSeconds: 240
```

## Recommendation: Current Setup is Optimal

**For our Chainlit application, the default TCP startup probe is perfect because:**

1. ✅ **Simplicity**: No custom health check code to maintain
2. ✅ **Reliability**: TCP check accurately reflects app health
3. ✅ **Fast Detection**: Immediate failure detection if port doesn't open
4. ✅ **No False Positives**: If Chainlit is running, it's healthy
5. ✅ **Works as Expected**: Production logs show "probe succeeded after 1 attempt"

## When You Might Need Custom Health Checks

Consider adding HTTP-based health checks if:
- App has complex initialization that can fail silently
- App can enter a degraded state while still accepting connections
- Need to check external dependencies (database, APIs) before accepting traffic
- Need to implement graceful shutdown with readiness probe

**For Chainlit**: None of these apply. The app is either running or not.

## How to Add Custom Health Checks (If Needed)

If you ever want to add custom health checks, here's how:

### 1. Create a Health Endpoint in Chainlit

```python
# In main.py or a separate module
from fastapi import FastAPI

app = FastAPI()

@app.get("/health")
async def health_check():
    # Check database
    db_ok = await check_database()
    # Check embedder
    embedder_ok = await check_embedder()

    if db_ok and embedder_ok:
        return {"status": "healthy"}
    else:
        return {"status": "unhealthy"}, 503
```

### 2. Configure Cloud Run Service

```bash
gcloud run services update cwe-chatbot \
  --region us-central1 \
  --set-env-vars="..." \
  --update-env-vars=... \
  --args="..." \
  --liveness-probe="httpGet,path=/health,port=8080,initialDelaySeconds=10,periodSeconds=30" \
  --readiness-probe="httpGet,path=/ready,port=8080,initialDelaySeconds=5,periodSeconds=10"
```

But again, **this is NOT needed for our current setup**.

## Production Evidence

From production logs (2025-10-08):
```
2025-10-08 17:15:51 - Default STARTUP TCP probe succeeded after 1 attempt
```

The current TCP probe works perfectly. The app starts in ~10 seconds and the probe detects it immediately.

## References

- [Cloud Run Health Checks](https://cloud.google.com/run/docs/configuring/healthchecks)
- [Kubernetes Probes](https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/)
- [Docker HEALTHCHECK](https://docs.docker.com/engine/reference/builder/#healthcheck) (not used by Cloud Run)

---

**Last Updated**: 2025-10-08
**Status**: Production configuration verified and working
