"""
BLFinder — core/modules/source_code_scanner.py
Source Code Exposure & Static Bug-Pattern Scanner

Every other module in BLFinder attacks the API from the outside (fuzzing
parameters, replaying requests). This module instead goes after cases where
the *source code itself* leaks to the outside — either as raw files
(exposed .git/.env/backup/credential files), as reconstructable JS via
exposed source maps, as an open directory listing, or as a stray backup
archive/database dump — and then statically greps that source for
code-level bug patterns that no black-box request would ever surface
(disabled TLS verification, eval/innerHTML sinks, postMessage handlers with
no origin check, hardcoded internal hostnames, commented-out auth checks).

This is deliberately split from `recon/js_secret_extractor.py`, which
already handles credential/API-key pattern matching well. This module's job
is CODE-LOGIC bugs and SOURCE EXPOSURE, not secrets — the two are
complementary and both may fire on the same file.

Four phases, all driven from a single target URL — no external wordlist or
discovery engine required:

  Phase A — Source exposure sweep (runs once per host)
      Probes a large, curated list of VCS/config/backup/credential-file
      paths (.git/HEAD, .git/logs/HEAD, .env, .aws/credentials,
      .vscode/sftp.json, id_rsa, kubeconfig, terraform.tfstate, framework
      config files for Rails/Django/Laravel/Drupal/Magento/Joomla/Spring/
      .NET, ...). Every candidate has its own content validator — never
      just "got a 200" — and every probe is checked against a
      soft-404/SPA-catch-all canary fingerprint first, the same
      anti-false-positive technique used by the wordlist discovery layer.
      A generic SPA that 200s everything will not generate a single
      finding here.

  Phase A2 — Backup archive / database dump sweep
      Probes common backup filenames (backup.zip, www.tar.gz, dump.sql,
      ...) combined with names derived from the target hostname itself.
      Validated by ASCII-safe magic bytes (ZIP), a binary-content heuristic
      (high invalid-UTF-8 ratio combined with an archive-ish Content-Type,
      since gzip/tar signatures don't survive text decoding), or a SQL-dump
      text signature — never a bare 200.

  Phase A3 — Directory listing discovery
      Every response this module sees (root, subdirectory probes, or any
      URL the rest of the scanner passes through `check()`) is checked
      against an autoindex/"Index of /" signature. A confirmed listing is
      reported on its own, and its linked entries are filtered to the
      ones that look sensitive by name (extension or keyword) and fetched;
      each is run through every Phase A/A2 content validator to classify
      it, or reported as an unclassified lead if none match. A bounded
      sweep of common subdirectories (admin/, api/, backup/, wp-content/,
      ...) feeds this same pipeline so folders reachable only by guessing
      their name are found too, not just ones linked from the homepage.

  Phase B — Source map reconstruction + static bug-pattern scan
      When a response looks like JS (content-type or `.js` URL), the module
      looks for a `sourceMappingURL` comment, fetches the referenced
      `.map` file, and — where the map embeds `sourcesContent` — statically
      scans the *original, unminified* source for dangerous patterns. If no
      map is available, a reduced pattern subset (the patterns that survive
      minification, e.g. `rejectUnauthorized: false`) is still run directly
      against the raw JS.

Resource caps are intentionally conservative (this runs on a phone over
cellular via Termux): map files >2MB are skipped, at most 20 JS files per
host are processed, the combined reconstructed-source scanned per host is
capped at ~500KB, exposure/archive/subdirectory probes run with bounded
concurrency (10 in flight), and following sensitive-looking links found in
directory listings is capped at 40 fetches per host.

Every static-pattern finding and every unclassified directory-listing lead
is reported as `confirmed=False` with an explicit "requires manual triage"
framing — regex/filename matches are leads, not proof, and this module
never inflates a heuristic match into a false sense of certainty. Only
findings backed by a specific content validator (a parsed git ref, a real
JSON key structure, a SQL-dump signature, an actual private-key header) or
a confirmed directory-listing signature are reported as confirmed.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import random
import re
import string
from urllib.parse import urljoin, urlparse

from ..models import Finding, Severity, ProofOfConcept

_MAX_MAP_BYTES = 2 * 1024 * 1024
_MAX_JS_FILES_PER_HOST = 20
_MAX_RECONSTRUCTED_CHARS = 500_000
_MAX_CONCURRENT_PROBES = 10
_MAX_LISTING_FOLLOWS_PER_HOST = 40
_MAX_LISTING_HREFS = 40
_MAX_ARCHIVE_BASENAMES = 12


def _is_git_ref(body: str, headers: dict) -> bool:
    return bool(re.match(r"^\s*ref:\s*refs/heads/\S+", body)) or bool(re.match(r"^\s*[0-9a-f]{40}\s*$", body.strip()))

def _is_git_config(body: str, headers: dict) -> bool:
    return "[core]" in body and "repositoryformatversion" in body

def _is_git_index(body: str, headers: dict) -> bool:
    return body.startswith("DIRC")

def _is_git_packed_refs(body: str, headers: dict) -> bool:
    stripped = body.strip()
    if stripped.startswith("# pack-refs"):
        return True
    return bool(re.search(r"^[0-9a-f]{40}\s+refs/", body, re.MULTILINE))

def _is_git_reflog(body: str, headers: dict) -> bool:
    return bool(re.search(r"^[0-9a-f]{40}\s[0-9a-f]{40}\s.+?\t", body, re.MULTILINE))

def _is_svn_wc_db(body: str, headers: dict) -> bool:
    return body.startswith("SQLite format 3")

def _is_hg_requires(body: str, headers: dict) -> bool:
    lines = [l.strip() for l in body.splitlines() if l.strip()]
    if not lines or len(lines) > 20:
        return False
    known = {"revlogv1", "store", "fncache", "dotencode", "generaldelta", "sparserevlog", "persistent-nodemap", "shared", "narrowhg"}
    return all(re.match(r"^[a-z0-9_-]+$", l) for l in lines) and any(l in known for l in lines)

def _is_env_file(body: str, headers: dict) -> bool:
    lines = [l for l in body.splitlines() if l.strip() and not l.strip().startswith("#")]
    if len(lines) < 2:
        return False
    kv_lines = sum(1 for l in lines if re.match(r"^[A-Z_][A-Z0-9_]*\s*=", l.strip()))
    return kv_lines >= max(2, len(lines) // 2)

def _is_aws_credentials(body: str, headers: dict) -> bool:
    return "[default]" in body and "aws_access_key_id" in body.lower()

def _is_ssh_private_key(body: str, headers: dict) -> bool:
    return bool(re.search(r"-----BEGIN (RSA|OPENSSH|EC|DSA) ?PRIVATE KEY-----", body))

def _is_generic_private_key(body: str, headers: dict) -> bool:
    return bool(re.search(r"-----BEGIN (?:ENCRYPTED )?PRIVATE KEY-----", body))

def _is_vscode_sftp(body: str, headers: dict) -> bool:
    try:
        data = json.loads(body)
    except Exception:
        return False
    if isinstance(data, list):
        data = data[0] if data else {}
    return isinstance(data, dict) and "host" in data and ("password" in data or "privateKeyPath" in data)

def _is_npmrc_token(body: str, headers: dict) -> bool:
    return bool(re.search(r"_authToken\s*=\s*\S+", body))

def _is_php_backup(body: str, headers: dict) -> bool:
    return "<?php" in body and bool(re.search(r"DB_(PASSWORD|PASS|HOST)|define\(", body, re.IGNORECASE))

def _is_docker_compose(body: str, headers: dict) -> bool:
    return "services:" in body and ("image:" in body or "build:" in body)

def _is_django_settings(body: str, headers: dict) -> bool:
    return "SECRET_KEY" in body and ("DEBUG" in body or "ALLOWED_HOSTS" in body)

def _is_htpasswd(body: str, headers: dict) -> bool:
    lines = [l for l in body.splitlines() if l.strip()]
    return bool(lines) and all(re.match(r"^[^:]+:\$?\w*\$?[\w./$]+$", l) for l in lines[:5])

def _is_htaccess_auth(body: str, headers: dict) -> bool:
    return "AuthUserFile" in body or ("AuthType Basic" in body and "AuthName" in body)

def _is_web_config(body: str, headers: dict) -> bool:
    return "<configuration" in body and ("<connectionStrings" in body or "<appSettings" in body)

def _is_appsettings_json(body: str, headers: dict) -> bool:
    try:
        data = json.loads(body)
    except Exception:
        return False
    return isinstance(data, dict) and "ConnectionStrings" in data

def _is_rails_database_yml(body: str, headers: dict) -> bool:
    return "adapter:" in body and "password:" in body and bool(re.search(r"^\s*(development|production|test):\s*$", body, re.MULTILINE))

def _is_rails_secrets_yml(body: str, headers: dict) -> bool:
    return "secret_key_base:" in body

def _is_rails_master_key(body: str, headers: dict) -> bool:
    return bool(re.match(r"^[0-9a-f]{32}\s*$", body.strip()))

def _is_git_credentials(body: str, headers: dict) -> bool:
    return bool(re.search(r"https?://[^:/\s]+:[^@/\s]+@\S+", body))

def _is_netrc(body: str, headers: dict) -> bool:
    return bool(re.search(r"machine\s+\S+\s+login\s+\S+\s+password\s+\S+", body))

def _is_pypirc(body: str, headers: dict) -> bool:
    return "[pypi]" in body and ("password" in body.lower() or "repository" in body.lower())

def _is_auth_json(body: str, headers: dict) -> bool:
    try:
        data = json.loads(body)
    except Exception:
        return False
    return isinstance(data, dict) and ("http-basic" in data or "github-oauth" in data)

def _is_laravel_log(body: str, headers: dict) -> bool:
    return bool(re.search(r"\[\d{4}-\d{2}-\d{2}[^\]]*\]\s+\w+\.(ERROR|CRITICAL|ALERT|EMERGENCY)", body))

def _is_gcp_service_account(body: str, headers: dict) -> bool:
    try:
        data = json.loads(body)
    except Exception:
        return False
    return isinstance(data, dict) and data.get("type") == "service_account" and "private_key" in data

def _is_google_oauth_client(body: str, headers: dict) -> bool:
    try:
        data = json.loads(body)
    except Exception:
        return False
    if not isinstance(data, dict):
        return False
    section = data.get("installed") or data.get("web")
    return isinstance(section, dict) and "client_secret" in section

def _is_terraform_state(body: str, headers: dict) -> bool:
    try:
        data = json.loads(body)
    except Exception:
        return False
    return isinstance(data, dict) and "terraform_version" in data and "resources" in data

def _is_kubeconfig(body: str, headers: dict) -> bool:
    return "apiVersion:" in body and "clusters:" in body and "users:" in body and (
        "client-key-data:" in body or "token:" in body or "password:" in body
    )

def _is_authorized_keys(body: str, headers: dict) -> bool:
    lines = [l.strip() for l in body.splitlines() if l.strip() and not l.strip().startswith("#")]
    if not lines:
        return False
    return all(l.split(" ", 1)[0] in ("ssh-rsa", "ssh-ed25519", "ssh-dss", "ecdsa-sha2-nistp256") for l in lines[:5])

def _is_ssh_config(body: str, headers: dict) -> bool:
    return bool(re.search(r"^\s*Host\s+\S+", body, re.MULTILINE)) and "IdentityFile" in body

def _is_pgpass(body: str, headers: dict) -> bool:
    lines = [l for l in body.splitlines() if l.strip() and not l.strip().startswith("#")]
    if not lines:
        return False
    matches = sum(1 for l in lines if len(l.split(":")) >= 5)
    return matches >= max(1, len(lines) // 2)

def _is_my_cnf(body: str, headers: dict) -> bool:
    return "[client]" in body and bool(re.search(r"password\s*=", body))

def _is_drupal_settings(body: str, headers: dict) -> bool:
    return "$databases" in body and "'password'" in body

def _is_magento_env(body: str, headers: dict) -> bool:
    return "'password'" in body and "'connection'" in body and ("return array" in body or "return [" in body)

def _is_joomla_config(body: str, headers: dict) -> bool:
    return "$password" in body and "class JConfig" in body

def _is_spring_config(body: str, headers: dict) -> bool:
    return "spring.datasource.password" in body or (
        "datasource:" in body and "password:" in body and "spring:" in body
    )

def _is_ds_store(body: str, headers: dict) -> bool:
    return body.startswith("\x00\x00\x00\x01Bud1")


def _content_type(headers: dict) -> str:
    for k, v in (headers or {}).items():
        if k.lower() == "content-type":
            return (v or "").lower()
    return ""

_SQL_DUMP_RE = re.compile(
    r"--\s*(MySQL dump|PostgreSQL database dump|phpMyAdmin SQL Dump)"
    r"|CREATE TABLE.{0,3000}?INSERT INTO",
    re.IGNORECASE | re.DOTALL,
)

def _is_sql_dump(body: str, headers: dict) -> bool:
    return bool(_SQL_DUMP_RE.search(body[:20_000]))

def _is_zip_signature(body: str, headers: dict) -> bool:
    return body[:4] in ("PK\x03\x04", "PK\x05\x06", "PK\x07\x08")

def _looks_like_binary_archive(body: str, headers: dict) -> bool:
    if _is_zip_signature(body, headers):
        return True
    ct = _content_type(headers)
    if not any(t in ct for t in ("zip", "gzip", "x-tar", "x-7z", "x-rar", "octet-stream")):
        return False
    sample = body[:2000]
    if len(sample) < 200:
        return False
    replacement_ratio = sample.count("\ufffd") / len(sample)
    return replacement_ratio > 0.05

def _is_archive_or_dump(body: str, headers: dict) -> bool:
    if not body:
        return False
    return _looks_like_binary_archive(body, headers) or _is_sql_dump(body, headers)


_EXPOSURE_CHECKS = [
    (".git/HEAD",              _is_git_ref,            "Exposed .git Repository (HEAD)",        Severity.CRITICAL, "CWE-527"),
    (".git/config",            _is_git_config,         "Exposed .git Repository (config)",      Severity.CRITICAL, "CWE-527"),
    (".git/index",             _is_git_index,          "Exposed .git Repository (index)",       Severity.CRITICAL, "CWE-527"),
    (".git/logs/HEAD",         _is_git_reflog,         "Exposed .git Repository (reflog)",      Severity.CRITICAL, "CWE-527"),
    (".git/packed-refs",       _is_git_packed_refs,    "Exposed .git Repository (packed-refs)", Severity.CRITICAL, "CWE-527"),
    (".svn/wc.db",             _is_svn_wc_db,          "Exposed .svn Repository (wc.db)",       Severity.CRITICAL, "CWE-527"),
    (".hg/requires",           _is_hg_requires,        "Exposed .hg Repository (requires)",     Severity.HIGH,     "CWE-527"),
    (".env",                   _is_env_file,           "Exposed .env Configuration File",       Severity.CRITICAL, "CWE-200"),
    (".env.local",             _is_env_file,           "Exposed .env.local Configuration File", Severity.CRITICAL, "CWE-200"),
    (".env.production",        _is_env_file,           "Exposed .env.production File",          Severity.CRITICAL, "CWE-200"),
    (".env.staging",           _is_env_file,           "Exposed .env.staging File",             Severity.CRITICAL, "CWE-200"),
    (".env.dev",               _is_env_file,           "Exposed .env.dev File",                 Severity.HIGH,     "CWE-200"),
    (".env.backup",            _is_env_file,           "Exposed .env Backup File",              Severity.CRITICAL, "CWE-200"),
    (".env.old",               _is_env_file,           "Exposed .env Backup File (.old)",       Severity.CRITICAL, "CWE-200"),
    (".env~",                  _is_env_file,           "Exposed .env Backup File (~)",          Severity.CRITICAL, "CWE-200"),
    (".aws/credentials",       _is_aws_credentials,    "Exposed AWS Credentials File",          Severity.CRITICAL, "CWE-522"),
    (".ssh/id_rsa",            _is_ssh_private_key,    "Exposed SSH Private Key",               Severity.CRITICAL, "CWE-522"),
    ("id_rsa",                 _is_ssh_private_key,    "Exposed SSH Private Key",               Severity.CRITICAL, "CWE-522"),
    ("id_dsa",                 _is_ssh_private_key,    "Exposed SSH Private Key",               Severity.CRITICAL, "CWE-522"),
    ("id_ecdsa",               _is_ssh_private_key,    "Exposed SSH Private Key",               Severity.CRITICAL, "CWE-522"),
    ("id_ed25519",             _is_ssh_private_key,    "Exposed SSH Private Key",               Severity.CRITICAL, "CWE-522"),
    ("server.key",             _is_generic_private_key,"Exposed Private Key File",              Severity.CRITICAL, "CWE-522"),
    ("privatekey.key",         _is_generic_private_key,"Exposed Private Key File",              Severity.CRITICAL, "CWE-522"),
    (".ssh/authorized_keys",   _is_authorized_keys,    "Exposed SSH authorized_keys",            Severity.LOW,      "CWE-200"),
    (".ssh/config",            _is_ssh_config,         "Exposed SSH Client Config",              Severity.LOW,      "CWE-200"),
    (".pgpass",                _is_pgpass,             "Exposed PostgreSQL .pgpass Credentials", Severity.CRITICAL, "CWE-522"),
    (".my.cnf",                _is_my_cnf,             "Exposed MySQL Client Credentials (.my.cnf)", Severity.CRITICAL, "CWE-522"),
    (".vscode/sftp.json",      _is_vscode_sftp,        "Exposed VS Code SFTP Credentials",      Severity.CRITICAL, "CWE-522"),
    (".npmrc",                 _is_npmrc_token,        "Exposed .npmrc Registry Auth Token",    Severity.HIGH,     "CWE-522"),
    (".git-credentials",       _is_git_credentials,    "Exposed .git-credentials File",         Severity.CRITICAL, "CWE-522"),
    (".netrc",                 _is_netrc,              "Exposed .netrc Credentials File",       Severity.CRITICAL, "CWE-522"),
    (".pypirc",                _is_pypirc,             "Exposed .pypirc Credentials File",      Severity.HIGH,     "CWE-522"),
    ("auth.json",              _is_auth_json,          "Exposed Composer auth.json",            Severity.HIGH,     "CWE-522"),
    ("config.php.bak",         _is_php_backup,         "Exposed PHP Config Backup File",        Severity.CRITICAL, "CWE-530"),
    ("wp-config.php.bak",      _is_php_backup,         "Exposed WordPress Config Backup File",  Severity.CRITICAL, "CWE-530"),
    ("wp-config.php.save",     _is_php_backup,         "Exposed WordPress Config Backup File",  Severity.CRITICAL, "CWE-530"),
    ("wp-config.php.orig",     _is_php_backup,         "Exposed WordPress Config Backup File",  Severity.CRITICAL, "CWE-530"),
    ("wp-config.php~",         _is_php_backup,         "Exposed WordPress Config Backup File",  Severity.CRITICAL, "CWE-530"),
    ("docker-compose.yml",     _is_docker_compose,     "Exposed docker-compose.yml",            Severity.HIGH,     "CWE-200"),
    ("docker-compose.yml.bak", _is_docker_compose,     "Exposed docker-compose.yml Backup",     Severity.HIGH,     "CWE-200"),
    ("settings.py",            _is_django_settings,    "Exposed Django settings.py",            Severity.CRITICAL, "CWE-200"),
    (".htpasswd",              _is_htpasswd,           "Exposed .htpasswd Credential File",     Severity.HIGH,     "CWE-522"),
    (".htaccess",              _is_htaccess_auth,      "Exposed .htaccess Revealing Auth Config", Severity.LOW,   "CWE-200"),
    ("web.config",             _is_web_config,         "Exposed IIS web.config",                Severity.HIGH,     "CWE-200"),
    ("appsettings.json",       _is_appsettings_json,   "Exposed .NET appsettings.json",         Severity.HIGH,     "CWE-200"),
    ("appsettings.Development.json", _is_appsettings_json, "Exposed .NET appsettings.Development.json", Severity.HIGH, "CWE-200"),
    ("config/database.yml",    _is_rails_database_yml, "Exposed Rails database.yml",            Severity.CRITICAL, "CWE-200"),
    ("config/secrets.yml",     _is_rails_secrets_yml,  "Exposed Rails secrets.yml",              Severity.CRITICAL, "CWE-200"),
    ("config/master.key",      _is_rails_master_key,   "Exposed Rails master.key",               Severity.CRITICAL, "CWE-522"),
    ("storage/logs/laravel.log", _is_laravel_log,      "Exposed Laravel Application Log",       Severity.MEDIUM,   "CWE-532"),
    ("service-account.json",   _is_gcp_service_account,"Exposed GCP Service Account Key",       Severity.CRITICAL, "CWE-522"),
    ("gcp-key.json",           _is_gcp_service_account,"Exposed GCP Service Account Key",       Severity.CRITICAL, "CWE-522"),
    ("credentials.json",       _is_google_oauth_client,"Exposed Google OAuth Client Credentials", Severity.CRITICAL, "CWE-522"),
    ("terraform.tfstate",      _is_terraform_state,    "Exposed Terraform State File",          Severity.CRITICAL, "CWE-200"),
    ("terraform.tfstate.backup", _is_terraform_state,  "Exposed Terraform State Backup",        Severity.CRITICAL, "CWE-200"),
    (".kube/config",           _is_kubeconfig,         "Exposed Kubernetes kubeconfig",         Severity.CRITICAL, "CWE-522"),
    ("kubeconfig",             _is_kubeconfig,         "Exposed Kubernetes kubeconfig",         Severity.CRITICAL, "CWE-522"),
    ("sites/default/settings.php", _is_drupal_settings,"Exposed Drupal settings.php",           Severity.CRITICAL, "CWE-200"),
    ("app/etc/env.php",        _is_magento_env,        "Exposed Magento env.php",               Severity.CRITICAL, "CWE-200"),
    ("configuration.php",      _is_joomla_config,      "Exposed Joomla configuration.php",      Severity.CRITICAL, "CWE-200"),
    ("application.yml",        _is_spring_config,      "Exposed Spring Boot application.yml",   Severity.CRITICAL, "CWE-200"),
    ("application.properties", _is_spring_config,      "Exposed Spring Boot application.properties", Severity.CRITICAL, "CWE-200"),
    (".DS_Store",              _is_ds_store,           "Exposed .DS_Store (Directory Metadata)", Severity.LOW,     "CWE-200"),
]

_HIGH_VALUE_CHECKS = [
    (".git/HEAD",         _is_git_ref,             "Exposed .git Repository (HEAD)",   Severity.CRITICAL, "CWE-527"),
    (".git/config",       _is_git_config,          "Exposed .git Repository (config)", Severity.CRITICAL, "CWE-527"),
    (".env",              _is_env_file,            "Exposed .env Configuration File",  Severity.CRITICAL, "CWE-200"),
    (".env.local",        _is_env_file,            "Exposed .env.local Configuration File", Severity.CRITICAL, "CWE-200"),
    ("config.php.bak",    _is_php_backup,          "Exposed PHP Config Backup File",   Severity.CRITICAL, "CWE-530"),
    ("web.config",        _is_web_config,          "Exposed IIS web.config",           Severity.HIGH,      "CWE-200"),
    ("appsettings.json",  _is_appsettings_json,    "Exposed .NET appsettings.json",    Severity.HIGH,      "CWE-200"),
    ("docker-compose.yml",_is_docker_compose,      "Exposed docker-compose.yml",       Severity.HIGH,      "CWE-200"),
    (".ssh/id_rsa",       _is_ssh_private_key,     "Exposed SSH Private Key",          Severity.CRITICAL, "CWE-522"),
    (".htpasswd",         _is_htpasswd,            "Exposed .htpasswd Credential File",Severity.HIGH,      "CWE-522"),
]

_CONTENT_VALIDATORS = [(v, t, s, c) for (_, v, t, s, c) in _EXPOSURE_CHECKS]
_CONTENT_VALIDATORS.append((_is_archive_or_dump, "Exposed Backup/Archive File", Severity.HIGH, "CWE-530"))

def _classify_body(body: str, headers: dict) -> tuple | None:
    for validator, title, severity, cwe in _CONTENT_VALIDATORS:
        try:
            if validator(body, headers):
                return title, severity, cwe
        except Exception:
            continue
    return None


_ARCHIVE_BASENAMES = [
    "backup", "www", "site", "web", "html", "public_html", "source",
    "src", "old", "dump", "database", "db", "db_backup", "full_backup",
]
_ARCHIVE_EXTENSIONS = [".zip", ".tar.gz", ".sql"]

def _derive_hostname_basenames(host: str) -> list[str]:
    name = host.split(":")[0]
    parts = [p for p in name.split(".") if p]
    candidates = []
    if len(parts) >= 2:
        candidates.append(parts[-2])
    if parts:
        candidates.append(parts[0])
    return [c for c in dict.fromkeys(candidates) if c and c not in ("www", "api", "app")]


_COMMON_SUBDIRS = [
    "admin", "api", "app", "backend", "static", "assets", "uploads",
    "backup", "old", "dev", "staging", "test", "src", "public", "vendor",
    "include", "includes", "config", "tmp", "logs", "private",
    "wp-content", "wp-admin",
]

_SENSITIVE_HINT_RE = re.compile(
    r"\.(?:git|env|sql|zip|tar|gz|tgz|bak|old|save|swp|key|pem|pfx|p12|"
    r"db|sqlite3?|log|yml|yaml|json|config|ini|conf)(?:[?#]|$)"
    r"|secret|backup|dump|credential|password|private",
    re.IGNORECASE,
)

_DIR_LISTING_TITLE_RE = re.compile(r"<title>\s*index of\s*/[^<]*</title>", re.IGNORECASE)
_DIR_LISTING_H1_RE = re.compile(r"<h1>\s*index of\s*/[^<]*</h1>", re.IGNORECASE)
_HREF_RE = re.compile(r'href\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)

def _is_directory_listing(body: str) -> bool:
    sample = body[:4000]
    if not sample:
        return False
    if not (_DIR_LISTING_TITLE_RE.search(sample) or _DIR_LISTING_H1_RE.search(sample)):
        return False
    return sample.lower().count("href=") >= 2

def _extract_listing_hrefs(body: str, base_url: str) -> list[str]:
    hrefs: list[str] = []
    seen: set[str] = set()
    base_netloc = urlparse(base_url).netloc
    for m in _HREF_RE.finditer(body[:20_000]):
        href = m.group(1)
        if not href or href in ("../", "./", "/") or href.startswith("?"):
            continue
        if href.lower().startswith(("mailto:", "javascript:", "#")):
            continue
        absolute = urljoin(base_url, href)
        if urlparse(absolute).netloc != base_netloc:
            continue
        if absolute in seen:
            continue
        seen.add(absolute)
        hrefs.append(absolute)
        if len(hrefs) >= _MAX_LISTING_HREFS:
            break
    return hrefs


class _JSPattern:
    __slots__ = ("id", "regex", "title", "description", "severity", "cwe", "minified_safe")

    def __init__(self, id_, regex, title, description, severity, cwe, minified_safe=False):
        self.id = id_
        self.regex = regex
        self.title = title
        self.description = description
        self.severity = severity
        self.cwe = cwe
        self.minified_safe = minified_safe


_JS_PATTERNS = [
    _JSPattern(
        "disabled_tls_verify",
        re.compile(r"rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0", re.IGNORECASE),
        "TLS Certificate Verification Disabled in Source",
        "The source disables TLS certificate verification for outbound HTTPS "
        "requests, allowing man-in-the-middle interception of any traffic "
        "this code path sends (e.g. to internal services, webhooks, or "
        "third-party APIs).",
        Severity.HIGH, "CWE-295", minified_safe=True,
    ),
    _JSPattern(
        "eval_dynamic_code",
        re.compile(r"\beval\s*\(|new\s+Function\s*\("),
        "Dynamic Code Execution Sink (eval/Function)",
        "Use of `eval()` or `new Function()` found. If any part of the "
        "argument is influenced by user/URL/query input, this is a direct "
        "path to client-side code execution.",
        Severity.MEDIUM, "CWE-95", minified_safe=True,
    ),
    _JSPattern(
        "dom_xss_sink",
        re.compile(r"\.innerHTML\s*=|\.outerHTML\s*=|document\.write\s*\(|dangerouslySetInnerHTML"),
        "DOM XSS Sink Present",
        "A DOM XSS sink (`innerHTML`/`outerHTML`/`document.write`/"
        "`dangerouslySetInnerHTML`) was found. Requires manual triage to "
        "confirm whether the assigned value is attacker-influenced "
        "(URL params, postMessage data, API responses reflected without "
        "encoding).",
        Severity.MEDIUM, "CWE-79",
    ),
    _JSPattern(
        "postmessage_no_origin_check",
        re.compile(
            r"addEventListener\s*\(\s*['\"]message['\"]\s*,\s*(?:function\s*\([^)]*\)|\([^)]*\)\s*=>)\s*\{"
            r"(?:(?!\.origin).){0,200}\}",
            re.DOTALL,
        ),
        "postMessage Handler Without Origin Validation",
        "A `window.addEventListener('message', ...)` handler was found "
        "whose first ~200 characters of body do not reference `.origin`. "
        "If the handler acts on the message data (writes to the DOM, "
        "navigates, calls an API) without validating `event.origin`, any "
        "page can post messages to it — a common cross-origin data leak / "
        "DOM XSS vector.",
        Severity.MEDIUM, "CWE-346",
    ),
    _JSPattern(
        "hardcoded_internal_host",
        re.compile(
            r"""['"`]https?://(?:localhost|127\.0\.0\.1|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"""
            r"""192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|"""
            r"""[\w.-]*\.(?:internal|local|corp|intranet))[:/][^'"`]*['"`]""",
        ),
        "Hardcoded Internal Hostname/IP in Client Source",
        "Client-side source references an internal hostname or private IP "
        "range directly. This leaks internal network topology (useful for "
        "chaining into an SSRF target list) and may indicate an internal "
        "API endpoint reachable only from specific network positions.",
        Severity.LOW, "CWE-200", minified_safe=True,
    ),
    _JSPattern(
        "insecure_random_for_security_token",
        re.compile(r"Math\.random\(\)[^;]{0,80}(token|password|otp|reset|secret|session)", re.IGNORECASE),
        "Non-Cryptographic Randomness Used for Security-Sensitive Value",
        "`Math.random()` is used near a security-sensitive identifier "
        "(token/password/OTP/reset/session). `Math.random()` is not "
        "cryptographically secure and its output can be predicted, "
        "potentially allowing token/session prediction. Verify whether "
        "this generates an actual security value or just a UI key.",
        Severity.MEDIUM, "CWE-338",
    ),
    _JSPattern(
        "commented_out_auth_check",
        re.compile(
            r"//\s*(?:if\s*\(.*(?:auth|permission|role|admin|isLoggedIn).*\)|.*(?:return\s+403|return\s+401))",
            re.IGNORECASE,
        ),
        "Commented-Out Authorization/Authentication Check",
        "A commented-out line resembling an authorization/authentication "
        "check was found. This may indicate a security control that was "
        "temporarily disabled for debugging and never re-enabled — worth "
        "manual review to confirm the corresponding server-side check is "
        "still enforced.",
        Severity.LOW, "CWE-489",
    ),
    _JSPattern(
        "debug_bypass_flag",
        re.compile(r"(?:if\s*\(\s*(?:window\.)?(?:DEBUG|debug|__DEV__|isDev|bypassAuth)\b)", re.IGNORECASE),
        "Debug/Bypass Flag Gating Application Logic",
        "A debug/bypass flag (`DEBUG`, `__DEV__`, `bypassAuth`, ...) gates "
        "part of the application logic. If this flag can be influenced "
        "client-side (query param, localStorage, global var) it may allow "
        "toggling debug-only behavior in production. Manual review needed "
        "to confirm what the flag actually gates.",
        Severity.LOW, "CWE-489",
    ),
]

_MINIFIED_SAFE_PATTERNS = [p for p in _JS_PATTERNS if p.minified_safe]


class SourceCodeScanner:
    """
    Usage:
        scs = SourceCodeScanner(scanner)
        findings = await scs.check(url, method, status, headers, body)
        scanner.findings.extend(findings)
    """

    def __init__(self, scanner):
        self._scanner = scanner
        self._config = scanner.config
        self._request = scanner._request
        self._exposure_checked_hosts: set[str] = set()
        self._reported: set[tuple] = set()
        self._js_files_scanned_per_host: dict[str, int] = {}
        self._reconstructed_chars_per_host: dict[str, int] = {}
        self._listing_checked: set[str] = set()
        self._listing_follow_budget: dict[str, int] = {}

    async def check(
        self,
        url: str,
        method: str,
        status: int = 0,
        headers: dict | None = None,
        body: str = "",
    ) -> list[Finding]:
        findings: list[Finding] = []
        parsed = urlparse(url)
        host = parsed.netloc
        if not host:
            return findings
        headers = headers or {}

        if host not in self._exposure_checked_hosts:
            self._exposure_checked_hosts.add(host)
            findings.extend(await self._scan_source_exposure(parsed.scheme, host))

        listing_finding, hrefs = self._check_directory_listing(host, url, body)
        if listing_finding:
            findings.append(listing_finding)
        if hrefs:
            findings.extend(await self._follow_sensitive_links(host, hrefs))

        if self._looks_like_js(url, headers, body):
            budget = self._js_files_scanned_per_host.get(host, 0)
            if budget < _MAX_JS_FILES_PER_HOST:
                self._js_files_scanned_per_host[host] = budget + 1
                findings.extend(await self._scan_js_source(url, host, body))

        return findings

    async def _scan_source_exposure(self, scheme: str, host: str) -> list[Finding]:
        findings: list[Finding] = []
        base = f"{scheme}://{host}"
        canary_hash = await self._canary_hash(base)

        findings.extend(await self._probe_checks(host, base, canary_hash, _EXPOSURE_CHECKS))
        findings.extend(await self._scan_archives(host, base, canary_hash))
        findings.extend(await self._sweep_subdirs(host, base, canary_hash))

        return findings

    async def _probe_checks(self, host: str, base: str, canary_hash: str | None, checks: list) -> list[Finding]:
        sem = asyncio.Semaphore(_MAX_CONCURRENT_PROBES)

        async def probe(entry) -> Finding | None:
            path, validator, title, severity, cwe = entry
            key = (host, "exposure", path)
            if key in self._reported:
                return None
            probe_url = f"{base}/{path}"
            async with sem:
                try:
                    pstatus, pheaders, pbody, _ = await self._request("GET", probe_url)
                except Exception as e:
                    if self._config.verbose:
                        print(f"[!] SourceCodeScanner exposure probe error {probe_url}: {e}")
                    return None
            if pstatus not in (200, 201):
                return None
            if not pbody or len(pbody) < 5:
                return None
            if canary_hash and self._body_hash(pbody) == canary_hash:
                return None
            if not validator(pbody, pheaders or {}):
                return None
            self._reported.add(key)
            return self._build_exposure_finding(probe_url, path, title, severity, cwe, pbody)

        results = await asyncio.gather(*(probe(e) for e in checks), return_exceptions=True)
        return [r for r in results if isinstance(r, Finding)]

    async def _scan_archives(self, host: str, base: str, canary_hash: str | None) -> list[Finding]:
        names = list(dict.fromkeys(_ARCHIVE_BASENAMES + _derive_hostname_basenames(host)))[:_MAX_ARCHIVE_BASENAMES]
        checks = [
            (f"{name}{ext}", _is_archive_or_dump, "Exposed Backup/Archive File", Severity.HIGH, "CWE-530")
            for name in names
            for ext in _ARCHIVE_EXTENSIONS
        ]
        return await self._probe_checks(host, base, canary_hash, checks)

    async def _sweep_subdirs(self, host: str, base: str, canary_hash: str | None) -> list[Finding]:
        findings: list[Finding] = []
        sem = asyncio.Semaphore(_MAX_CONCURRENT_PROBES)

        async def probe_subdir(subdir: str):
            subdir_url = f"{base}/{subdir}/"
            async with sem:
                try:
                    sstatus, sheaders, sbody, _ = await self._request("GET", subdir_url)
                except Exception:
                    return None
            if sstatus not in (200, 201) or not sbody:
                return None
            if canary_hash and self._body_hash(sbody) == canary_hash:
                return None
            return subdir, subdir_url, sheaders or {}, sbody

        results = await asyncio.gather(*(probe_subdir(s) for s in _COMMON_SUBDIRS), return_exceptions=True)
        live_subdirs = [r for r in results if isinstance(r, tuple)]

        for subdir, subdir_url, _headers, sbody in live_subdirs:
            listing_finding, hrefs = self._check_directory_listing(host, subdir_url, sbody)
            if listing_finding:
                findings.append(listing_finding)
            if hrefs:
                findings.extend(await self._follow_sensitive_links(host, hrefs))

        for subdir, _url, _headers, _body in live_subdirs:
            subdir_checks = [(f"{subdir}/{p}", v, t, s, c) for (p, v, t, s, c) in _HIGH_VALUE_CHECKS]
            findings.extend(await self._probe_checks(host, base, canary_hash, subdir_checks))

        return findings

    def _check_directory_listing(self, host: str, url: str, body: str) -> tuple[Finding | None, list[str]]:
        if not body or url in self._listing_checked:
            return None, []
        self._listing_checked.add(url)
        if not _is_directory_listing(body):
            return None, []
        hrefs = _extract_listing_hrefs(body, url)
        return self._build_listing_finding(url, hrefs), hrefs

    async def _follow_sensitive_links(self, host: str, hrefs: list[str]) -> list[Finding]:
        findings: list[Finding] = []
        budget = self._listing_follow_budget.get(host, _MAX_LISTING_FOLLOWS_PER_HOST)
        candidates = [h for h in hrefs if _SENSITIVE_HINT_RE.search(h)]

        for link_url in candidates:
            if budget <= 0:
                break
            key = (host, "listing_follow", link_url)
            if key in self._reported:
                continue
            self._reported.add(key)
            budget -= 1
            try:
                lstatus, lheaders, lbody, _ = await self._request("GET", link_url)
            except Exception as e:
                if self._config.verbose:
                    print(f"[!] SourceCodeScanner listing-follow error {link_url}: {e}")
                continue
            if lstatus not in (200, 201) or not lbody:
                continue
            classified = _classify_body(lbody, lheaders or {})
            if classified:
                title, severity, cwe = classified
                path = urlparse(link_url).path.lstrip("/")
                findings.append(self._build_exposure_finding(link_url, path, title, severity, cwe, lbody))
            else:
                findings.append(self._build_unclassified_listed_finding(link_url))

        self._listing_follow_budget[host] = budget
        return findings

    async def _canary_hash(self, base: str) -> str | None:
        nonce = "".join(random.choices(string.ascii_lowercase + string.digits, k=12))
        canary_url = f"{base}/blfinder_src_canary_{nonce}_does_not_exist"
        try:
            status, _, body, _ = await self._request("GET", canary_url)
        except Exception:
            return None
        if status not in (200, 404) or not body:
            return None
        return self._body_hash(body)

    def _body_hash(self, body: str) -> str:
        return hashlib.md5(body[:500].encode("utf-8", errors="replace")).hexdigest()

    def _build_exposure_finding(self, url, path, title, severity, cwe, body) -> Finding:
        snippet = body[:400].replace("\n", " ")
        recommendation = {
            "CWE-527": (
                "Block access to `.git`/`.svn`/`.hg` directories at the web "
                "server or reverse-proxy layer (deny-by-default for dotfiles), "
                "and rotate any credentials that ever existed in the "
                "repository's history — a partial `.git` exposure is enough "
                "to reconstruct the full history and every secret ever "
                "committed, even if later removed."
            ),
            "CWE-200": (
                "Remove environment/config files from the web root entirely; "
                "they should never be served by the application server. "
                "Rotate every credential contained in the exposed file "
                "immediately, since it must be treated as fully compromised."
            ),
            "CWE-522": (
                "Remove the exposed credential/key file from the web root and "
                "rotate the corresponding credentials immediately. Store "
                "secrets in a secrets manager or environment variables "
                "injected at runtime, never as static files under the "
                "document root."
            ),
            "CWE-530": (
                "Remove editor/deploy backup files (`*.bak`, `*.swp`, `*.save`, "
                "`*~`) and backup archives/dumps from the web root — configure "
                "your deploy pipeline to exclude them, and add a web-server "
                "rule denying any request for a path ending in a backup-file "
                "or archive extension."
            ),
            "CWE-532": (
                "Move application log files outside the web-served document "
                "root, or restrict access to them at the web server layer. "
                "Review the exposed log for any leaked credentials, tokens, "
                "or internal paths and rotate/redact as needed."
            ),
        }.get(cwe, "Remove this file from the publicly accessible web root.")

        finding = Finding(
            title=title,
            severity=severity,
            category="Source Code Exposure",
            description=(
                f"`{url}` is publicly accessible and its content matched the "
                f"expected format for this file type (validated beyond a bare "
                f"200 status — confirmed against a soft-404 canary and a "
                f"content-shape check specific to this file)."
            ),
            request={"method": "GET", "url": url},
            response_summary=f"200 OK, content validated as {title.lower()}",
            evidence=f"Response snippet: {snippet}",
            recommendation=recommendation,
            cwe=cwe,
            cvss=9.1 if severity == Severity.CRITICAL else (7.5 if severity == Severity.HIGH else 5.3),
            owasp="OWASP Top 10 A05:2021 Security Misconfiguration",
            confirmed=True,
            confidence=93,
            confidence_reasons=[
                "Content matched a file-type-specific validator (not just HTTP 200)",
                "Response did not match the soft-404/SPA-catch-all canary fingerprint",
            ],
            endpoint=url,
            parameter="",
        )
        finding.poc = ProofOfConcept(
            summary=f"Publicly exposed {title.lower()}",
            curl_command=f'curl -sk "{url}" -i',
            python_script=f'import requests\nr = requests.get("{url}")\nprint(r.status_code)\nprint(r.text[:1000])\n',
            burp_request=f"GET /{path} HTTP/1.1\nHost: {urlparse(url).netloc}\nConnection: close\n\n",
            expected_result="The file downloads with content matching the description above.",
            steps=[f"Request `{url}` directly — no authentication required."],
        )
        return finding

    def _build_listing_finding(self, url: str, hrefs: list[str]) -> Finding:
        preview = ", ".join(h.rsplit("/", 1)[-1] or h for h in hrefs[:15])
        finding = Finding(
            title="Directory Listing Enabled",
            severity=Severity.MEDIUM,
            category="Source Code Exposure",
            description=(
                f"`{url}` returns a browsable directory index instead of a "
                f"normal page, exposing the names of every file and "
                f"subdirectory it contains ({len(hrefs)} entries found)."
            ),
            request={"method": "GET", "url": url},
            response_summary="200 OK, autoindex-style directory listing",
            evidence=f"Listed entries: {preview}" + (" ..." if len(hrefs) > 15 else ""),
            recommendation=(
                "Disable directory indexing at the web server (e.g. "
                "`Options -Indexes` in Apache, `autoindex off;` in nginx) and "
                "review every listed entry for anything that should not be "
                "publicly reachable."
            ),
            cwe="CWE-548",
            cvss=5.3,
            owasp="OWASP Top 10 A05:2021 Security Misconfiguration",
            confirmed=True,
            confidence=90,
            confidence_reasons=["Response matched a directory-listing/autoindex page signature"],
            endpoint=url,
            parameter="",
        )
        finding.poc = ProofOfConcept(
            summary="Directory listing exposes file/folder names",
            curl_command=f'curl -sk "{url}"',
            python_script=f'import requests\nr = requests.get("{url}")\nprint(r.text)\n',
            burp_request=f"GET {urlparse(url).path or '/'} HTTP/1.1\nHost: {urlparse(url).netloc}\nConnection: close\n\n",
            expected_result="The response body lists file and directory names.",
            steps=[f"Open `{url}` in a browser to view the listing."],
        )
        return finding

    def _build_unclassified_listed_finding(self, url: str) -> Finding:
        finding = Finding(
            title="Sensitive-Looking File Exposed via Directory Listing — Requires Manual Triage",
            severity=Severity.MEDIUM,
            category="Source Code Exposure",
            description=(
                f"`{url}` was reachable and its name suggests sensitive "
                f"content (backup/credential/database-related), but its body "
                f"did not match any known structured-format validator. "
                f"Review it manually before reporting."
            ),
            request={"method": "GET", "url": url},
            response_summary="200 OK, filename pattern suggests sensitive content",
            evidence="Discovered via a directory listing at a related path",
            recommendation=(
                "Manually review the file content; remove it from the web "
                "root if it contains anything sensitive."
            ),
            cwe="CWE-200",
            cvss=0.0,
            owasp="OWASP Top 10 A05:2021 Security Misconfiguration",
            confirmed=False,
            confidence=35,
            confidence_reasons=[
                "Filename pattern matched sensitive-file heuristics; content "
                "did not match a structured validator"
            ],
            false_positive_checks=[
                "Filename-based heuristic only — content was not validated "
                "against a known format"
            ],
            endpoint=url,
            parameter="",
        )
        finding.poc = ProofOfConcept(
            summary="Sensitive-looking file exposed",
            curl_command=f'curl -sk "{url}"',
            python_script=f'import requests\nr = requests.get("{url}")\nprint(r.text[:1000])\n',
            burp_request="",
            expected_result="Manually confirm whether the file content is sensitive.",
            steps=[f"Open `{url}` and inspect its content."],
        )
        return finding

    def _looks_like_js(self, url: str, headers: dict, body: str) -> bool:
        ct = ""
        for k, v in headers.items():
            if k.lower() == "content-type":
                ct = v.lower()
                break
        if "javascript" in ct or "ecmascript" in ct:
            return True
        if urlparse(url).path.endswith((".js", ".mjs", ".cjs")):
            return True
        return False

    async def _scan_js_source(self, url: str, host: str, body: str) -> list[Finding]:
        findings: list[Finding] = []

        map_url, map_content = await self._fetch_source_map(url, body)
        sources_content = self._extract_sources_content(map_content) if map_content else []

        char_budget = _MAX_RECONSTRUCTED_CHARS - self._reconstructed_chars_per_host.get(host, 0)

        if sources_content and char_budget > 0:
            combined = "\n".join(sources_content)[:char_budget]
            self._reconstructed_chars_per_host[host] = (
                self._reconstructed_chars_per_host.get(host, 0) + len(combined)
            )
            findings.extend(
                self._apply_patterns(url, host, combined, _JS_PATTERNS, source_label=f"reconstructed via {map_url}")
            )
        else:
            findings.extend(
                self._apply_patterns(url, host, body, _MINIFIED_SAFE_PATTERNS, source_label="raw/minified JS")
            )

        return findings

    async def _fetch_source_map(self, js_url: str, body: str) -> tuple[str, str]:
        m = re.search(r"//[#@]\s*sourceMappingURL=([^\s'\"]+)", body[-2000:])
        if not m:
            return "", ""
        map_ref = m.group(1)
        if map_ref.startswith("data:"):
            return "", ""
        map_url = urljoin(js_url, map_ref)
        try:
            status, headers, map_body, _ = await self._request("GET", map_url)
        except Exception as e:
            if self._config.verbose:
                print(f"[!] SourceCodeScanner map fetch error {map_url}: {e}")
            return "", ""
        if status != 200 or not map_body:
            return "", ""
        if len(map_body) > _MAX_MAP_BYTES:
            return "", ""
        return map_url, map_body

    def _extract_sources_content(self, map_body: str) -> list[str]:
        try:
            data = json.loads(map_body)
        except Exception:
            return []
        contents = data.get("sourcesContent") or []
        return [c for c in contents if isinstance(c, str) and c.strip()]

    def _apply_patterns(self, url, host, text, patterns, source_label: str) -> list[Finding]:
        findings = []
        for pattern in patterns:
            key = (host, "js_pattern", pattern.id, url)
            if key in self._reported:
                continue
            m = pattern.regex.search(text)
            if not m:
                continue
            self._reported.add(key)
            start = max(0, m.start() - 60)
            snippet = text[start:m.end() + 60].replace("\n", " ")
            findings.append(self._build_js_pattern_finding(url, pattern, snippet, source_label))
        return findings

    def _build_js_pattern_finding(self, url, pattern: "_JSPattern", snippet: str, source_label: str) -> Finding:
        finding = Finding(
            title=f"{pattern.title} — Requires Manual Triage",
            severity=pattern.severity,
            category="Static Source Code Analysis",
            description=(
                f"{pattern.description}\n\nFound in `{url}` ({source_label}). "
                f"This is a static pattern match, not a runtime-confirmed "
                f"vulnerability — verify the surrounding context before "
                f"reporting it as a confirmed bug."
            ),
            request={"method": "GET", "url": url},
            response_summary="Static pattern match in client-side source",
            evidence=f"...{snippet}...",
            recommendation=(
                "Review the surrounding code path manually to confirm "
                "exploitability before reporting; see the pattern-specific "
                "guidance in the description above."
            ),
            cwe=pattern.cwe,
            cvss=0.0,
            owasp="OWASP Top 10 A05:2021 Security Misconfiguration",
            confirmed=False,
            confidence=45,
            confidence_reasons=[f"Static regex match for pattern `{pattern.id}`"],
            false_positive_checks=[
                "Static pattern match only — not confirmed against runtime behavior",
                "Requires manual review of surrounding code to confirm "
                "attacker influence over the relevant value/flag",
            ],
            endpoint=url,
            parameter="",
        )
        finding.poc = ProofOfConcept(
            summary=f"Static match: {pattern.title}",
            curl_command=f'curl -sk "{url}" -o source.js',
            python_script=(
                "import requests\n"
                f'r = requests.get("{url}")\n'
                "open('source.js', 'w').write(r.text)\n"
            ),
            burp_request="",
            expected_result="Manually confirm exploitability of the flagged code path.",
            steps=[f"Open `{url}` and locate: ...{snippet}..."],
        )
        return finding
