# Deployment Guide — Local AI Firewall

This guide covers building a Docker container and deploying the Local AI Firewall to production, with a focus on Kubernetes sidecar architecture.

---

## 1. Docker build

We recommend a multi-stage build to keep the production image tiny and secure.

Create a `Dockerfile` in the root of the project:

```dockerfile
# --- Build Stage ---
FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o ai-firewall main.go

# --- Production Stage ---
FROM alpine:3.19
RUN apk --no-cache add ca-certificates tzdata
WORKDIR /app
COPY --from=builder /app/ai-firewall .

# Run as non-root user for security
RUN adduser -D -u 10001 appuser
USER appuser

EXPOSE 8080
ENTRYPOINT ["./ai-firewall"]
```

Build and tag the image:
```bash
docker build -t localai/firewall:latest .
```

---

## 2. Kubernetes Sidecar Deployment (Recommended)

In enterprise environments, the most secure pattern is to run the firewall as a **sidecar container** inside the application pod. 

This ensures that:
1. The application communicates with the firewall over `localhost` (`127.0.0.1`), meaning unmasked prompts and API keys never traverse the physical network.
2. The firewall injects the credentials and masks the data before sending it out of the pod.

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: billing-service
  namespace: services
  labels:
    app: billing-service
spec:
  replicas: 2
  selector:
    matchLabels:
      app: billing-service
  template:
    metadata:
      labels:
        app: billing-service
    spec:
      containers:
        # --- 1. Main Application Container ---
        - name: application
          image: company/billing-service:v2.1
          env:
            # Point the app's AI SDK to the local sidecar proxy
            - name: ANTHROPIC_BASE_URL
              value: "http://127.0.0.1:8080"
            # Give the app a dummy placeholder key so the SDK doesn't fail
            - name: ANTHROPIC_API_KEY
              value: "local-firewall-placeholder"
          ports:
            - containerPort: 3000
          resources:
            limits:
              cpu: 500m
              memory: 256Mi
            requests:
              cpu: 100m
              memory: 128Mi

        # --- 2. Local AI Firewall Sidecar ---
        - name: ai-firewall
          image: localai/firewall:latest
          ports:
            - containerPort: 8080
              name: proxy-port
          env:
            # The real API key is injected from a Kubernetes Secret
            - name: FORWARD_API_KEY
              valueFrom:
                secretKeyRef:
                  name: ai-secrets
                  key: anthropic-api-key
            - name: UPSTREAM_URL
              value: "https://api.anthropic.com"
            - name: FIREWALL_PORT
              value: "8080"
            - name: VAULT_SIZE_LIMIT
              value: "500"
            - name: LOG_LEVEL
              value: "info"
          resources:
            limits:
              cpu: 200m
              memory: 64Mi
            requests:
              cpu: 50m
              memory: 16Mi
          # Health probes verify the firewall status
          livenessProbe:
            httpGet:
              path: /health
              port: 8080
            initialDelaySeconds: 5
            periodSeconds: 10
          readinessProbe:
            httpGet:
              path: /health
              port: 8080
            initialDelaySeconds: 3
            periodSeconds: 5
```

---

## 3. Standalone Gateway Deployment

**Not supported.** Do not expose the current firewall as a shared service. It intentionally binds to loopback and does not implement client authentication, authorization, tenant policy, rate limiting, or a multi-tenant secret boundary. Run one sidecar per application workload instead.

The following former shared-gateway example is intentionally removed because it could expose a provider credential for unauthorised use and would imply security guarantees the current architecture does not provide.

<!--

```yaml
apiVersion: v1
kind: Service
metadata:
  name: ai-firewall-gateway
  namespace: security
spec:
  selector:
    app: ai-firewall-gateway
  ports:
    - protocol: TCP
      port: 80
      targetPort: 8080
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ai-firewall-gateway
  namespace: security
spec:
  replicas: 3
  selector:
    matchLabels:
      app: ai-firewall-gateway
  template:
    metadata:
      labels:
        app: ai-firewall-gateway
    spec:
      containers:
        - name: firewall
          image: localai/firewall:latest
          ports:
            - containerPort: 8080
          env:
            - name: FORWARD_API_KEY
              valueFrom:
                secretKeyRef:
                  name: shared-ai-keys
                  key: openai-api-key
            - name: UPSTREAM_URL
              value: "https://api.openai.com"
            - name: FIREWALL_PORT
              value: "8080"
          resources:
            limits:
              cpu: 500m
              memory: 128Mi
            requests:
              cpu: 100m
              memory: 32Mi
          livenessProbe:
            httpGet:
              path: /health
              port: 8080
          readinessProbe:
            httpGet:
              path: /health
              port: 8080
```
Then point all cluster services to `http://ai-firewall-gateway.security.svc.cluster.local` as their AI API host.
-->
