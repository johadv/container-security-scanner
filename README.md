# Container Security Scanner

A simple command-line tool for checking the security posture of Dockerfiles and Kubernetes/YAML files.

## Features

- Dockerfile scanning for common security issues
- Kubernetes manifest checks for pod- and container-level settings
- JSON or text output
- RBAC-style permission checks
- Works locally on macOS and Linux
- Works inside Docker and Colima as well

## Installation

### Local usage

You only need Python 3. The wrapper script uses the system Python by default and creates a local `.venv` only when YAML scanning needs the `PyYAML` dependency.

```bash
chmod +x scan.sh
./scan.sh example.insecure.Dockerfile
./scan.sh example.secure.Dockerfile
```

### Direct Python usage

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
python security_scanner.py example.insecure.Dockerfile
python security_scanner.py example.secure.Dockerfile
```

## Usage

### Basic usage

```bash
./scan.sh .
./scan.sh example.insecure.Dockerfile
./scan.sh example.secure.Dockerfile
./scan.sh deployment.yaml
```

### Advanced options

```bash
./scan.sh --user admin .
./scan.sh --output json .
python3 security_scanner.py . --user developer --output text
python3 security_scanner.py . --action verify --user admin
```

## How It Works

1. Input
   You pass the tool a Dockerfile, a Kubernetes YAML file, or a full directory.
2. Detection
   The wrapper script selects the right Python runtime and the scanner detects whether it should inspect Dockerfiles, YAML files, or both.
3. Rule checks
   The scanner applies rule-based security checks such as `Check minimal image`, `Check no root user`, `Check only production dependencies`, `runAsNonRoot`, and `allowPrivilegeEscalation`.
4. Report
   The tool prints a text or JSON report grouped by severity: `ERROR`, `HIGH`, `MEDIUM`, and `LOW`.
5. CI/CD result
   If `HIGH` or `ERROR` findings are present, the process exits with a non-zero status so the scan can fail a pipeline.

```text
Developer files
   |
   v
scan.sh
   |
   v
security_scanner.py
   |
   +--> Dockerfile checks
   |      - minimal image
   |      - no root user
   |      - production-only dependencies
   |
   +--> Kubernetes/YAML checks
          - securityContext
          - runAsNonRoot
          - allowPrivilegeEscalation
          - image tag and pull policy
   |
   v
Security report
   |
   +--> text/json output
   +--> non-zero exit on HIGH/ERROR
```

## Colima on macOS

If your Docker CLI is using Colima, the project works the same way as it does on Linux.

```bash
colima start
docker build -f Dockerfile.scanner -t container-security-scanner .
docker run --rm -v "$PWD:/workspace" container-security-scanner /workspace
docker run --rm -v "$PWD:/workspace" container-security-scanner /workspace/example.insecure.Dockerfile --output json
docker run --rm -v "$PWD:/workspace" container-security-scanner /workspace/example.secure.Dockerfile --output json
```

Notes:

- `colima start` is only needed on macOS if Docker is not already connected to Colima.
- On Linux, the same `docker build` and `docker run` commands work without Colima.

## Example Files

- `example.insecure.Dockerfile` is intentionally insecure and is meant to demonstrate how the scanner reports findings.
- `example.secure.Dockerfile` is a minimal example that follows the key checks more closely: no root user, a minimal base image, and a simple runtime-only setup.

## Checks

### Dockerfile

- `Check minimal image`
- `Check no root user`
- `Check only production dependencies`
- `USER root`
- `FROM ...:latest`
- `apt-get install` without `--no-install-recommends`
- Multi-line `RUN` commands are supported

### Kubernetes/YAML

- Missing pod-level `securityContext`
- Missing `runAsNonRoot`
- Missing container-level `securityContext`
- Missing `allowPrivilegeEscalation: false`
- Missing `imagePullPolicy`
- Image without an explicit tag
- Supports common workload types such as `Deployment`, `StatefulSet`, `DaemonSet`, `Job`, and `CronJob` through pod template extraction

## RBAC configuration

You can pass a custom JSON configuration with `--rbac-config`.

```json
{
  "roles": {
    "admin": ["read", "write", "scan", "sign", "verify"],
    "developer": ["read", "scan"],
    "viewer": ["read"]
  },
  "users": {
    "default": "developer",
    "admin": "admin",
    "developer": "developer",
    "viewer": "viewer"
  }
}
```

## CI/CD

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run Security Scanner
        run: |
          chmod +x scan.sh
          ./scan.sh .
```
