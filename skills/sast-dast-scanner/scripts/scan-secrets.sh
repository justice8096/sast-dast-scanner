#!/bin/bash

# SAST/DAST Scanner - Hardcoded Secrets Detection
# Searches for API keys, credentials, tokens, and other sensitive data
# in source code using grep/ripgrep pattern matching

set -e

TARGET_DIR="${1:-.}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Color codes
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1"; }

# Counter for findings
FINDINGS=0

# Use ripgrep if available, otherwise grep
SEARCH_CMD="grep"
if command -v rg >/dev/null 2>&1; then
    SEARCH_CMD="rg"
    log_info "Using ripgrep for faster scanning"
else
    log_info "Using grep (consider installing ripgrep for better performance)"
fi

# Exclude paths
EXCLUDE_DIRS="--exclude-dir=node_modules --exclude-dir=.git --exclude-dir=.venv --exclude-dir=venv --exclude-dir=vendor --exclude-dir=dist --exclude-dir=build"
EXCLUDE_FILES="--exclude=*.min.js --exclude=*.map --exclude=*.lock"

if [[ "$SEARCH_CMD" == "rg" ]]; then
    EXCLUDE_DIRS="--glob '!node_modules' --glob '!.git' --glob '!.venv' --glob '!venv' --glob '!vendor' --glob '!dist' --glob '!build'"
    EXCLUDE_FILES="--glob '!*.min.js' --glob '!*.map' --glob '!*.lock'"
fi

# Function to search and report
search_pattern() {
    local pattern="$1"
    local description="$2"
    local severity="${3:-HIGH}"
    local cwe="${4:-CWE-798}"

    log_info "Searching for: $description"

    if [[ "$SEARCH_CMD" == "rg" ]]; then
        matches=$(rg -i "$pattern" "$TARGET_DIR" $EXCLUDE_DIRS -c 2>/dev/null || echo "0")
    else
        matches=$(grep -r -i "$pattern" "$TARGET_DIR" $EXCLUDE_DIRS $EXCLUDE_FILES 2>/dev/null | wc -l || echo "0")
    fi

    if [[ "$matches" -gt 0 ]]; then
        log_warn "$description: $matches potential match(es) found"
        FINDINGS=$((FINDINGS + matches))

        # Show sample matches (first 3)
        if [[ "$SEARCH_CMD" == "rg" ]]; then
            rg -i "$pattern" "$TARGET_DIR" $EXCLUDE_DIRS --max-count=3 2>/dev/null | sed 's/^/    /' || true
        else
            grep -r -i "$pattern" "$TARGET_DIR" $EXCLUDE_DIRS $EXCLUDE_FILES 2>/dev/null | head -3 | sed 's/^/    /' || true
        fi
        echo ""
    fi
}

main() {
    echo "=================================================="
    echo "   SAST/DAST Scanner - Secrets Detection"
    echo "=================================================="
    echo "Target: $TARGET_DIR"
    echo ""

    if [[ ! -d "$TARGET_DIR" ]]; then
        log_error "Target directory not found: $TARGET_DIR"
        exit 1
    fi

    cd "$TARGET_DIR"

    # AWS Credentials
    search_pattern "AKIA[0-9A-Z]{16}" "AWS Access Keys" "CRITICAL" "CWE-798"
    search_pattern "aws_secret_access_key\s*=|aws_secret_access_key['\"]" "AWS Secret Keys" "CRITICAL" "CWE-798"
    search_pattern "aws_access_key_id\s*=" "AWS Access Key IDs" "CRITICAL" "CWE-798"

    # GitHub / GitLab Tokens
    search_pattern "ghp_[a-zA-Z0-9]{36}" "GitHub Personal Access Token" "CRITICAL" "CWE-798"
    search_pattern "github_token['\"]?\s*[:=]" "GitHub Token Assignment" "CRITICAL" "CWE-798"
    search_pattern "gl.*?['\"]?[A-Za-z0-9_-]{20,}['\"]?" "GitLab Token Pattern" "CRITICAL" "CWE-798"

    # OAuth & API Keys
    search_pattern "client_id['\"]?\s*[:=]\s*['\"]?[A-Za-z0-9]{20,}" "OAuth Client ID" "HIGH" "CWE-798"
    search_pattern "client_secret['\"]?\s*[:=]" "OAuth Client Secret" "CRITICAL" "CWE-798"
    search_pattern "api[_-]?key['\"]?\s*[:=]" "Generic API Key" "HIGH" "CWE-798"

    # JWT Secrets
    search_pattern "secret['\"]?\s*[:=]\s*['\"]?[a-zA-Z0-9\!\@\#\$\%\^\&\*]{10,}" "JWT Secret" "CRITICAL" "CWE-798"
    search_pattern "jwt[_-]?secret['\"]?\s*[:=]" "JWT Secret Assignment" "CRITICAL" "CWE-798"
    search_pattern "jwtSecret" "JWT Secret Variable" "CRITICAL" "CWE-798"

    # Database Credentials
    search_pattern "mongodb[+a-z]*://[^:]*:[^@]*@" "MongoDB Connection with Password" "CRITICAL" "CWE-798"
    search_pattern "postgres[a-z]*://[^:]*:[^@]*@" "PostgreSQL Connection String" "CRITICAL" "CWE-798"
    search_pattern "mysql://[^:]*:[^@]*@" "MySQL Connection String" "CRITICAL" "CWE-798"
    search_pattern "password['\"]?\s*[:=]\s*['\"]" "Database Password" "CRITICAL" "CWE-798"
    search_pattern "db[_-]?password['\"]?\s*[:=]" "DB Password Assignment" "CRITICAL" "CWE-798"

    # Private Keys
    search_pattern "-----BEGIN PRIVATE KEY-----" "Private Key (PKCS8)" "CRITICAL" "CWE-798"
    search_pattern "-----BEGIN RSA PRIVATE KEY-----" "RSA Private Key" "CRITICAL" "CWE-798"
    search_pattern "-----BEGIN DSA PRIVATE KEY-----" "DSA Private Key" "CRITICAL" "CWE-798"
    search_pattern "-----BEGIN EC PRIVATE KEY-----" "EC Private Key" "CRITICAL" "CWE-798"

    # Slack & Discord Tokens
    search_pattern "xox[baprs]-[0-9a-zA-Z]{10,48}" "Slack Token" "CRITICAL" "CWE-798"
    search_pattern "discord.*?token['\"]?\s*[:=]" "Discord Token" "CRITICAL" "CWE-798"

    # Payment & Cloud Provider Keys
    search_pattern "sk_live_[a-zA-Z0-9]{20,}" "Stripe Live Key" "CRITICAL" "CWE-798"
    search_pattern "sk_test_[a-zA-Z0-9]{20,}" "Stripe Test Key" "HIGH" "CWE-798"
    search_pattern "pk_live_[a-zA-Z0-9]{20,}" "Stripe Publishable Key" "MEDIUM" "CWE-798"
    search_pattern "auth0['\"]?:\s*['\"][a-zA-Z0-9_-]{20,}['\"]" "Auth0 Credentials" "CRITICAL" "CWE-798"

    # Other API Credentials
    search_pattern "sendgrid[_-]?api[_-]?key['\"]?\s*[:=]" "SendGrid API Key" "CRITICAL" "CWE-798"
    search_pattern "mailgun[_-]?api[_-]?key['\"]?\s*[:=]" "Mailgun API Key" "CRITICAL" "CWE-798"
    search_pattern "twilio[_-]?auth[_-]?token['\"]?\s*[:=]" "Twilio Auth Token" "CRITICAL" "CWE-798"

    # Hardcoded Credentials
    search_pattern "password\s*=\s*['\"][a-zA-Z0-9!@#$%]{6,}" "Hardcoded Password (non-env)" "HIGH" "CWE-798"
    search_pattern "username['\"]?\s*[:=]\s*['\"]?admin" "Default Admin Username" "MEDIUM" "CWE-798"

    # Sensitive configuration
    search_pattern "FLASK_ENV['\"]?\s*=\s*['\"]?development" "Flask Debug Mode" "HIGH" "CWE-489"
    search_pattern "DEBUG\s*=\s*True|DEBUG\s*=\s*true" "Debug Mode Enabled" "HIGH" "CWE-489"
    search_pattern "allow_hosts\s*=\s*\[.*\*.*\]" "Insecure ALLOWED_HOSTS" "HIGH" "CWE-942"

    # Summary
    echo "=================================================="
    echo "   Secrets Scan Summary"
    echo "=================================================="
    echo ""

    if [[ $FINDINGS -eq 0 ]]; then
        log_success "No secrets found!"
    else
        log_warn "Found $FINDINGS potential secret(s)"
        log_warn "Manual review required - some matches may be false positives"
    fi

    echo ""
    log_info "Scan complete"
    echo ""

    # Recommendations
    if [[ $FINDINGS -gt 0 ]]; then
        echo "=================================================="
        echo "   Remediation Recommendations"
        echo "=================================================="
        echo ""
        echo "1. DO NOT commit secrets to version control"
        echo "2. Move all secrets to environment variables:"
        echo "   - export API_KEY='value'"
        echo "   - Use .env files (add to .gitignore)"
        echo "3. Use secret management tools:"
        echo "   - AWS Secrets Manager"
        echo "   - HashiCorp Vault"
        echo "   - Azure Key Vault"
        echo "4. Rotate compromised credentials immediately"
        echo "5. Scan git history for leaked secrets:"
        echo "   - git log -p | grep -i 'password\\|secret\\|key'"
        echo ""
    fi

    return $FINDINGS
}

main "$@"
