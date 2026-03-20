#!/bin/bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${ROOT_DIR}/.venv"
PYTHON_BIN="${PYTHON_BIN:-python3}"
SCANNER_PYTHON="${PYTHON_BIN}"

echo "Container Security Scanner"
echo "========================"

if ! command -v "${PYTHON_BIN}" >/dev/null 2>&1; then
    echo "Python 3 is required but not installed. Please install Python 3."
    exit 1
fi

ensure_venv() {
    if [ ! -x "${VENV_DIR}/bin/python" ]; then
        echo "Creating local virtual environment in ${VENV_DIR}"
        "${PYTHON_BIN}" -m venv "${VENV_DIR}"
    fi
}

needs_yaml_support() {
    local path=$1

    if [ -d "$path" ]; then
        if find "$path" \( -name "*.yaml" -o -name "*.yml" \) -print -quit | grep -q .; then
            return 0
        fi
        return 1
    fi

    case "$path" in
        *.yaml|*.yml)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

ensure_requirements() {
    if ! "${VENV_DIR}/bin/python" -c "import yaml, json" >/dev/null 2>&1; then
        echo "Installing required packages into ${VENV_DIR}"
        "${VENV_DIR}/bin/python" -m pip install -r "${ROOT_DIR}/requirements.txt"
    fi
}

select_python() {
    local path=$1

    if ! needs_yaml_support "$path"; then
        SCANNER_PYTHON="${PYTHON_BIN}"
        return
    fi

    if "${PYTHON_BIN}" -c "import yaml, json" >/dev/null 2>&1; then
        SCANNER_PYTHON="${PYTHON_BIN}"
        return
    fi

    ensure_venv
    ensure_requirements
    SCANNER_PYTHON="${VENV_DIR}/bin/python"
}

run_scan() {
    local path=$1
    local user=${2:-default}
    local output=${3:-text}

    echo "Scanning: $path"
    echo "User: $user"
    echo "Output: $output"
    echo "---"

    "${SCANNER_PYTHON}" "${ROOT_DIR}/security_scanner.py" "$path" --user "$user" --output "$output"
}

show_help() {
    echo "Usage: $0 [OPTIONS] PATH"
    echo ""
    echo "Options:"
    echo "  -u, --user USER     User for RBAC (default: default)"
    echo "  -o, --output FORMAT Output format: text or json (default: text)"
    echo "  -h, --help          Show this help"
    echo ""
    echo "Examples:"
    echo "  $0 .                              # Scan the current directory"
    echo "  $0 example.Dockerfile             # Scan a specific Dockerfile"
    echo "  $0 --user admin deployment.yaml   # Scan with admin permissions"
    echo "  $0 --output json .                # JSON output"
}

USER_NAME="default"
OUTPUT="text"
PATH_ARG=""

while [[ $# -gt 0 ]]; do
    case $1 in
        -u|--user)
            USER_NAME="$2"
            shift 2
            ;;
        -o|--output)
            OUTPUT="$2"
            shift 2
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            PATH_ARG="$1"
            shift
            ;;
    esac
done

if [ -z "$PATH_ARG" ]; then
    echo "Error: No path specified"
    show_help
    exit 1
fi

select_python "$PATH_ARG"
run_scan "$PATH_ARG" "$USER_NAME" "$OUTPUT"
