#!/usr/bin/env python3
"""
Simple Security Scanner for Dockerfiles and YAML files.

This tool scans Dockerfiles and YAML files for common security issues,
including supply chain security checks, image scanning recommendations,
and basic RBAC-style configuration validation.
"""

import argparse
import json
import os
from pathlib import Path
from typing import Dict, List, NotRequired, Optional, TypedDict, cast

JSONDict = Dict[str, object]


class DockerfileLine(TypedDict):
    line: int
    content: str


class SecurityIssue(TypedDict):
    file: str
    severity: str
    category: str
    message: str
    line: NotRequired[int]


class RBACConfig(TypedDict):
    roles: Dict[str, List[str]]
    users: Dict[str, str]


class SecurityScanner:
    def __init__(self, rbac_config: Optional[str] = None):
        self.rbac_config = self.load_rbac_config(rbac_config)

    def load_rbac_config(self, config_path: Optional[str]) -> RBACConfig:
        """Load RBAC configuration from JSON file."""
        if config_path and os.path.exists(config_path):
            with open(config_path, "r") as f:
                return cast(RBACConfig, json.load(f))
        return {
            "roles": {
                "admin": ["read", "write", "scan", "sign", "verify"],
                "developer": ["read", "scan"],
                "viewer": ["read"],
            },
            "users": {
                "default": "developer",
                "admin": "admin",
                "developer": "developer",
                "viewer": "viewer",
            },
        }

    def check_permissions(self, user: str, action: str) -> bool:
        """Check if user has permission for action."""
        user_role = self.rbac_config["users"].get(user, "viewer")
        role_permissions = self.rbac_config["roles"].get(user_role, [])
        return action in role_permissions

    def make_issue(
        self,
        file_path: str,
        severity: str,
        category: str,
        message: str,
        line: Optional[int] = None,
    ) -> SecurityIssue:
        issue: SecurityIssue = {
            "file": file_path,
            "severity": severity,
            "category": category,
            "message": message,
        }
        if line is not None:
            issue["line"] = line
        return issue

    def get_dict(self, value: object) -> Optional[JSONDict]:
        """Return the object if it is a string-keyed dictionary."""
        if isinstance(value, dict):
            typed_value: JSONDict = cast(JSONDict, value)
            return typed_value
        return None

    def get_dict_list(self, value: object) -> Optional[List[JSONDict]]:
        """Return a list of dictionaries if the value matches the expected shape."""
        if not isinstance(value, list):
            return None

        items: List[object] = cast(List[object], value)
        result: List[JSONDict] = []
        for item in items:
            item_dict = self.get_dict(item)
            if item_dict is None:
                return None
            result.append(item_dict)
        return result

    def get_str(self, mapping: JSONDict, key: str) -> Optional[str]:
        """Return a string value from a dictionary if present."""
        value = mapping.get(key)
        return value if isinstance(value, str) else None

    def normalize_dockerfile_lines(self, content: str) -> List[DockerfileLine]:
        """Join Dockerfile line continuations while keeping original line numbers."""
        normalized_lines: List[DockerfileLine] = []
        current_line = ""
        start_line = 1

        for line_number, raw_line in enumerate(content.splitlines(), start=1):
            stripped = raw_line.strip()
            if not stripped or stripped.startswith("#"):
                if current_line:
                    normalized_lines.append({"line": start_line, "content": current_line.strip()})
                    current_line = ""
                continue

            if not current_line:
                start_line = line_number

            current_line = f"{current_line} {stripped}".strip() if current_line else stripped
            if stripped.endswith("\\"):
                current_line = current_line[:-1].strip()
                continue

            normalized_lines.append({"line": start_line, "content": current_line.strip()})
            current_line = ""

        if current_line:
            normalized_lines.append({"line": start_line, "content": current_line.strip()})

        return normalized_lines

    def scan_dockerfile(self, file_path: str) -> List[SecurityIssue]:
        """Scan Dockerfile for security issues."""
        issues: List[SecurityIssue] = []
        try:
            with open(file_path, "r") as f:
                content = f.read()

            lines = self.normalize_dockerfile_lines(content)

            minimal_image_keywords = (
                "alpine",
                "distroless",
                "scratch",
                "busybox",
                "ubi-micro",
                "wolfi",
                "slim",
            )
            production_install_patterns = (
                "apt-get install",
                "apk add",
                "yum install",
                "dnf install",
                "npm install",
                "npm ci",
                "yarn install",
                "pnpm install",
                "pip install",
                "poetry install",
                "bundle install",
                "composer install",
            )
            production_only_markers = (
                "--omit=dev",
                "--production",
                "requirements-prod",
                "requirements/prod",
                "prod-requirements",
                "poetry install --only main",
                "bundle install --without development test",
                "composer install --no-dev",
            )

            from_entries = [entry for entry in lines if entry["content"].upper().startswith("FROM")]
            for entry in from_entries:
                image_reference = entry["content"].split()[1].lower() if len(entry["content"].split()) > 1 else ""
                if image_reference and not any(keyword in image_reference for keyword in minimal_image_keywords):
                    issues.append(
                        self.make_issue(
                            file_path,
                            "MEDIUM",
                            "Container Hardening",
                            f"Check minimal image: base image '{image_reference}' does not look minimal. Prefer alpine, distroless, slim, scratch, or another minimal runtime image",
                            entry["line"],
                        )
                    )

            for entry in lines:
                line = entry["content"]
                if line.upper().startswith("USER ROOT"):
                    issues.append(
                        self.make_issue(
                            file_path,
                            "HIGH",
                            "Container Security",
                            "Check no root user: Dockerfile runs as root. Set a dedicated non-root USER before runtime",
                            entry["line"],
                        )
                    )

            for entry in lines:
                line = entry["content"]
                if line.upper().startswith("FROM") and ":latest" in line.lower():
                    issues.append(
                        self.make_issue(
                            file_path,
                            "MEDIUM",
                            "Supply Chain Security",
                            "Using latest tag - pin to specific version for reproducibility",
                            entry["line"],
                        )
                    )

            for entry in lines:
                line = entry["content"]
                if line.upper().startswith("RUN"):
                    if (
                        "apt-get update" in line
                        and "apt-get install" in line
                        and "--no-install-recommends" not in line
                    ):
                        issues.append(
                            self.make_issue(
                                file_path,
                                "LOW",
                                "Supply Chain Security",
                                "Consider using --no-install-recommends to reduce attack surface",
                                entry["line"],
                            )
                        )

                    lowered = line.lower()
                    if any(pattern in lowered for pattern in production_install_patterns):
                        if not any(marker in lowered for marker in production_only_markers):
                            issues.append(
                                self.make_issue(
                                    file_path,
                                    "MEDIUM",
                                    "Dependency Hygiene",
                                    "Check only production dependencies: install command does not clearly exclude dev/test dependencies",
                                    entry["line"],
                                )
                            )

        except Exception as e:
            issues.append(self.make_issue(file_path, "ERROR", "File Error", f"Error scanning Dockerfile: {str(e)}"))

        return issues

    def scan_yaml(self, file_path: str) -> List[SecurityIssue]:
        """Scan YAML file for security issues."""
        issues: List[SecurityIssue] = []
        try:
            import yaml

            with open(file_path, "r") as f:
                documents = cast(List[object], list(yaml.safe_load_all(f)))

            for document in documents:
                manifest = self.get_dict(document)
                if manifest is not None and "apiVersion" in manifest and "kind" in manifest:
                    typed_manifest: JSONDict = manifest
                    issues.extend(self.scan_kubernetes_manifest(typed_manifest, file_path))

        except ImportError:
            issues.append(
                self.make_issue(
                    file_path,
                    "ERROR",
                    "Dependency Error",
                    "PyYAML is required to scan YAML files. Install it with pip install -r requirements.txt",
                )
            )
        except Exception as e:
            if e.__class__.__name__ == "YAMLError":
                issues.append(self.make_issue(file_path, "ERROR", "YAML Error", f"YAML parsing error: {str(e)}"))
            else:
                issues.append(self.make_issue(file_path, "ERROR", "File Error", f"Error scanning YAML file: {str(e)}"))

        return issues

    def extract_pod_spec(self, manifest: JSONDict) -> JSONDict:
        """Return the pod spec regardless of Kubernetes workload type."""
        spec = self.get_dict(manifest.get("spec"))
        if spec is None:
            return {}

        template = self.get_dict(spec.get("template"))
        template_spec = self.get_dict(template.get("spec")) if template is not None else None
        if template_spec is not None:
            return template_spec

        job_template = self.get_dict(spec.get("jobTemplate"))
        if job_template is not None:
            job_template_spec = self.get_dict(job_template.get("spec"))
            if job_template_spec is not None:
                nested_template = self.get_dict(job_template_spec.get("template"))
                nested_spec = self.get_dict(nested_template.get("spec")) if nested_template is not None else None
                if nested_spec is not None:
                    return nested_spec

        return spec

    def scan_container_specs(self, containers: List[JSONDict], file_path: str) -> List[SecurityIssue]:
        """Scan individual container specs."""
        issues: List[SecurityIssue] = []
        for i, container in enumerate(containers):
            if "securityContext" not in container:
                issues.append(
                    self.make_issue(
                        file_path,
                        "MEDIUM",
                        "Container Security",
                        f"Container {i} missing securityContext",
                    )
                )
            else:
                cont_sec_ctx = self.get_dict(container.get("securityContext"))
                if cont_sec_ctx is None or "allowPrivilegeEscalation" not in cont_sec_ctx:
                    issues.append(
                        self.make_issue(
                            file_path,
                            "LOW",
                            "Container Security",
                            f"Container {i} should set allowPrivilegeEscalation: false",
                        )
                    )

            image = self.get_str(container, "image") or ""
            if image and ":" not in image:
                issues.append(
                    self.make_issue(
                        file_path,
                        "LOW",
                        "Supply Chain Security",
                        f"Container {i} image is not pinned to a specific tag",
                    )
                )

            image_pull_policy = self.get_str(container, "imagePullPolicy")
            if image_pull_policy is None or image_pull_policy == "Always":
                issues.append(
                    self.make_issue(
                        file_path,
                        "LOW",
                        "Supply Chain Security",
                        f"Container {i} should use specific image tags and pull policy",
                    )
                )
        return issues

    def scan_kubernetes_manifest(self, manifest: JSONDict, file_path: str) -> List[SecurityIssue]:
        """Scan Kubernetes manifest for security issues."""
        issues: List[SecurityIssue] = []
        spec: JSONDict = self.extract_pod_spec(manifest)
        if not spec:
            return issues

        if "securityContext" not in spec:
            issues.append(
                self.make_issue(file_path, "MEDIUM", "Container Security", "Missing pod-level securityContext")
            )
        else:
            sec_ctx = self.get_dict(spec.get("securityContext"))
            if sec_ctx is None or "runAsNonRoot" not in sec_ctx:
                issues.append(
                    self.make_issue(file_path, "HIGH", "Container Security", "securityContext missing runAsNonRoot")
                )

        containers = self.get_dict_list(spec.get("containers"))
        if containers is not None:
            issues.extend(self.scan_container_specs(containers, file_path))

        return issues

    def scan_directory(self, directory: str) -> List[SecurityIssue]:
        """Scan directory for Dockerfiles and YAML files."""
        all_issues: List[SecurityIssue] = []
        path = Path(directory)

        dockerfiles = list(path.rglob("Dockerfile*"))
        for dockerfile in dockerfiles:
            all_issues.extend(self.scan_dockerfile(str(dockerfile)))

        yaml_files = list(path.rglob("*.yaml")) + list(path.rglob("*.yml"))
        for yaml_file in yaml_files:
            all_issues.extend(self.scan_yaml(str(yaml_file)))

        return all_issues

    def generate_report(self, issues: List[SecurityIssue], output_format: str = "text") -> str:
        """Generate security report."""
        if output_format == "json":
            return json.dumps(issues, indent=2)
        if output_format == "text":
            report = "Security Scan Report\n"
            report += "=" * 50 + "\n\n"

            if not issues:
                report += "No security issues found!\n"
                return report

            severities = ["ERROR", "HIGH", "MEDIUM", "LOW"]
            for severity in severities:
                sev_issues = [i for i in issues if i.get("severity") == severity]
                if sev_issues:
                    report += f"{severity} Severity Issues ({len(sev_issues)}):\n"
                    report += "-" * 30 + "\n"
                    for issue in sev_issues:
                        report += f"File: {issue['file']}\n"
                        if "line" in issue:
                            report += f"Line: {issue['line']}\n"
                        report += f"Category: {issue['category']}\n"
                        report += f"Message: {issue['message']}\n\n"

            return report
        return ""


def main():
    parser = argparse.ArgumentParser(description="Simple Security Scanner for container files")
    parser.add_argument("path", help="File or directory to scan")
    parser.add_argument("--user", default="default", help="User for RBAC check")
    parser.add_argument("--rbac-config", help="Path to RBAC configuration JSON file")
    parser.add_argument("--output", choices=["text", "json"], default="text", help="Output format")
    parser.add_argument(
        "--action",
        choices=["scan", "sign", "verify"],
        default="scan",
        help="Action to perform",
    )

    args = parser.parse_args()

    scanner = SecurityScanner(args.rbac_config)

    if not scanner.check_permissions(args.user, args.action):
        print(f"User '{args.user}' does not have permission to perform '{args.action}'")
        return 1

    if args.action == "scan":
        if os.path.isfile(args.path):
            if args.path.lower().endswith((".yaml", ".yml")):
                issues = scanner.scan_yaml(args.path)
            elif "dockerfile" in args.path.lower():
                issues = scanner.scan_dockerfile(args.path)
            else:
                print("Unsupported file type. Only YAML and Dockerfile are supported.")
                return 1
        elif os.path.isdir(args.path):
            issues = scanner.scan_directory(args.path)
        else:
            print(f"Path {args.path} does not exist")
            return 1

        report = scanner.generate_report(issues, args.output)
        print(report)

        high_issues = [i for i in issues if i.get("severity") in ["HIGH", "ERROR"]]
        return 1 if high_issues else 0

    if args.action == "sign":
        print("Image signing not yet implemented. Use cosign externally.")
        return 0

    if args.action == "verify":
        print("Image verification not yet implemented. Use cosign externally.")
        return 0

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
