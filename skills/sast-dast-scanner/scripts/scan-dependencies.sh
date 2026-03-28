#!/bin/bash

# SAST/DAST Scanner - Dependency Vulnerability Auditing
# Detects and reports known vulnerabilities in project dependencies
# Supports: npm, pip, cargo, go, Maven, Gradle

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_DIR="${1:-.}"

# Color codes for output
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[OK]${NC} $1"
}

# Check if tool is installed
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Scan Node.js dependencies
scan_npm() {
    local manifest="$1"
    if [[ ! -f "$manifest" ]]; then
        return 0
    fi

    log_info "Scanning npm dependencies (package.json)..."

    if command_exists npm; then
        log_info "Running 'npm audit'..."

        if npm audit --prefix "$(dirname "$manifest")" --audit-level=moderate 2>/dev/null; then
            log_success "npm audit passed (no moderate/high/critical vulnerabilities)"
        else
            log_warn "npm audit found vulnerabilities"
            npm audit --prefix "$(dirname "$manifest")" --json > npm-audit.json 2>/dev/null || true
        fi
    else
        log_warn "npm not installed, skipping npm audit"
    fi
}

# Scan Python dependencies
scan_pip() {
    if [[ ! -f "$1" ]] && [[ ! -f "$2" ]]; then
        return 0
    fi

    log_info "Scanning Python dependencies..."

    if command_exists pip-audit; then
        log_info "Running 'pip-audit'..."
        if pip-audit --desc --output json 2>/dev/null | tee pip-audit.json; then
            log_success "pip-audit passed"
        else
            log_warn "pip-audit found vulnerabilities"
        fi
    elif command_exists safety; then
        log_info "Running 'safety check'..."
        safety check --json > safety-report.json 2>/dev/null || log_warn "safety found vulnerabilities"
    else
        log_warn "pip-audit or safety not installed, skipping Python audit"
    fi
}

# Scan Rust dependencies
scan_cargo() {
    local manifest="$1"
    if [[ ! -f "$manifest" ]]; then
        return 0
    fi

    log_info "Scanning Rust dependencies (Cargo.toml)..."

    if command_exists cargo; then
        log_info "Running 'cargo audit'..."
        if cargo audit --json > cargo-audit.json 2>/dev/null; then
            log_success "cargo audit passed"
        else
            log_warn "cargo audit found vulnerabilities"
        fi
    else
        log_warn "cargo not installed, skipping Cargo audit"
    fi
}

# Scan Go dependencies
scan_go() {
    local manifest="$1"
    if [[ ! -f "$manifest" ]]; then
        return 0
    fi

    log_info "Scanning Go dependencies (go.mod)..."

    if command_exists go; then
        log_info "Running 'go list' vulnerability scan..."
        if go list -json -m all 2>/dev/null | tee go-deps.json; then
            if command_exists nancy; then
                nancy sleuth < go-deps.json > nancy-report.json 2>/dev/null || \
                    log_warn "nancy found vulnerabilities"
            else
                log_warn "nancy not installed (install: go install github.com/sonatype-nexus-community/nancy@latest)"
            fi
        fi
    else
        log_warn "go not installed, skipping Go audit"
    fi
}

# Scan Maven dependencies
scan_maven() {
    local manifest="$1"
    if [[ ! -f "$manifest" ]]; then
        return 0
    fi

    log_info "Scanning Maven dependencies (pom.xml)..."

    if command_exists mvn; then
        log_info "Running 'maven dependency check'..."
        mvn -f "$manifest" dependency-check:check 2>/dev/null || \
            log_warn "Maven dependency-check found vulnerabilities"
    else
        log_warn "Maven not installed, skipping Maven audit"
    fi
}

# Scan Gradle dependencies
scan_gradle() {
    local manifest="$1"
    if [[ ! -f "$manifest" ]]; then
        return 0
    fi

    log_info "Scanning Gradle dependencies..."

    if command_exists gradle; then
        log_info "Running 'gradle dependencyCheckAnalyze'..."
        gradle -b "$manifest" dependencyCheckAnalyze 2>/dev/null || \
            log_warn "Gradle dependency-check found vulnerabilities"
    else
        log_warn "gradle not installed, skipping Gradle audit"
    fi
}

# Main scanning logic
main() {
    echo "=================================================="
    echo "   SAST/DAST Scanner - Dependency Audit"
    echo "=================================================="
    echo "Target: $TARGET_DIR"
    echo ""

    if [[ ! -d "$TARGET_DIR" ]]; then
        log_error "Target directory not found: $TARGET_DIR"
        exit 1
    fi

    cd "$TARGET_DIR"

    vulnerabilities_found=0

    # Detect and scan package managers
    if [[ -f "package.json" ]]; then
        scan_npm "package.json"
        vulnerabilities_found=$((vulnerabilities_found + $?))
    fi

    if [[ -f "requirements.txt" ]] || [[ -f "Pipfile" ]] || [[ -f "pyproject.toml" ]]; then
        scan_pip "requirements.txt" "Pipfile"
        vulnerabilities_found=$((vulnerabilities_found + $?))
    fi

    if [[ -f "Cargo.toml" ]]; then
        scan_cargo "Cargo.toml"
        vulnerabilities_found=$((vulnerabilities_found + $?))
    fi

    if [[ -f "go.mod" ]]; then
        scan_go "go.mod"
        vulnerabilities_found=$((vulnerabilities_found + $?))
    fi

    if [[ -f "pom.xml" ]]; then
        scan_maven "pom.xml"
        vulnerabilities_found=$((vulnerabilities_found + $?))
    fi

    if [[ -f "build.gradle" ]]; then
        scan_gradle "build.gradle"
        vulnerabilities_found=$((vulnerabilities_found + $?))
    fi

    # Summary
    echo ""
    echo "=================================================="
    echo "   Scan Summary"
    echo "=================================================="

    if [[ -f npm-audit.json ]]; then
        vulnerabilities=$(grep -o '"critical":[0-9]*' npm-audit.json | grep -o '[0-9]*')
        log_info "npm: Critical vulnerabilities: $vulnerabilities"
    fi

    if [[ -f pip-audit.json ]]; then
        log_info "pip-audit: Check pip-audit.json for details"
    fi

    if [[ -f cargo-audit.json ]]; then
        vulnerabilities=$(grep -o '"vulnerabilities":[0-9]*' cargo-audit.json | grep -o '[0-9]*')
        log_info "cargo: Vulnerabilities: $vulnerabilities"
    fi

    if [[ -f nancy-report.json ]]; then
        log_info "nancy: Check nancy-report.json for details"
    fi

    echo ""
    log_info "Dependency scanning complete"
    log_info "JSON reports generated in current directory"
    echo ""

    return $vulnerabilities_found
}

main "$@"
