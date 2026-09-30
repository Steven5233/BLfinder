import types

import pytest

from blfinder.core.models import Finding
from blfinder.core.modules import source_code_scanner as scs


def make_scanner(responses, verbose=False):
    async def fake_request(method, url, **kwargs):
        if url in responses:
            status, headers, body = responses[url]
            return status, headers, body, 0.01
        return 404, {}, "not found", 0.01

    fake = types.SimpleNamespace(
        config=types.SimpleNamespace(verbose=verbose),
        _request=fake_request,
    )
    return scs.SourceCodeScanner(fake)


def test_is_git_index():
    assert scs._is_git_index("DIRC\x00\x00\x00\x02rest", {}) is True
    assert scs._is_git_index("not git index", {}) is False


def test_is_git_packed_refs():
    body = "# pack-refs with: peeled fully-peeled sorted\nabc123 refs/heads/main\n"
    assert scs._is_git_packed_refs(body, {}) is True
    assert scs._is_git_packed_refs("random text", {}) is False


def test_is_git_reflog():
    body = "0000000000000000000000000000000000000000 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa Dev <dev@x.com> 1690000000 +0000\tcommit (initial): init\n"
    assert scs._is_git_reflog(body, {}) is True
    assert scs._is_git_reflog("nothing here", {}) is False


def test_is_svn_wc_db():
    assert scs._is_svn_wc_db("SQLite format 3\x00rest", {}) is True
    assert scs._is_svn_wc_db("plain text", {}) is False


def test_is_hg_requires():
    assert scs._is_hg_requires("revlogv1\nstore\nfncache\n", {}) is True
    assert scs._is_hg_requires("<html>not hg</html>", {}) is False


def test_is_generic_private_key():
    assert scs._is_generic_private_key("-----BEGIN PRIVATE KEY-----\nMIIB...\n", {}) is True
    assert scs._is_generic_private_key("no key here", {}) is False


def test_is_web_config():
    body = '<configuration><connectionStrings><add name="x" connectionString="y"/></connectionStrings></configuration>'
    assert scs._is_web_config(body, {}) is True
    assert scs._is_web_config("<html></html>", {}) is False


def test_is_appsettings_json():
    assert scs._is_appsettings_json('{"ConnectionStrings": {"Default": "Server=x;Password=y"}}', {}) is True
    assert scs._is_appsettings_json('{"foo": "bar"}', {}) is False
    assert scs._is_appsettings_json("not json", {}) is False


def test_is_rails_database_yml():
    body = "production:\n  adapter: postgresql\n  password: supersecret\n"
    assert scs._is_rails_database_yml(body, {}) is True
    assert scs._is_rails_database_yml("adapter: postgresql", {}) is False


def test_is_git_credentials():
    assert scs._is_git_credentials("https://user:hunter2@github.com\n", {}) is True
    assert scs._is_git_credentials("https://github.com\n", {}) is False


def test_is_netrc():
    assert scs._is_netrc("machine api.example.com login bob password secret123\n", {}) is True
    assert scs._is_netrc("nothing", {}) is False


def test_is_laravel_log():
    body = "[2026-01-01 12:00:00] production.ERROR: something broke {\"exception\":\"...\"}\n"
    assert scs._is_laravel_log(body, {}) is True
    assert scs._is_laravel_log("plain log line", {}) is False


def test_is_gcp_service_account():
    body = '{"type": "service_account", "private_key": "-----BEGIN PRIVATE KEY-----"}'
    assert scs._is_gcp_service_account(body, {}) is True
    assert scs._is_gcp_service_account('{"type": "user"}', {}) is False


def test_is_terraform_state():
    body = '{"terraform_version": "1.5.0", "resources": []}'
    assert scs._is_terraform_state(body, {}) is True
    assert scs._is_terraform_state('{"foo": "bar"}', {}) is False


def test_is_kubeconfig():
    body = "apiVersion: v1\nclusters:\n- cluster: {}\nusers:\n- user:\n    token: abc123\n"
    assert scs._is_kubeconfig(body, {}) is True
    assert scs._is_kubeconfig("apiVersion: v1\n", {}) is False


def test_is_pgpass():
    body = "db.example.com:5432:mydb:admin:supersecret\n"
    assert scs._is_pgpass(body, {}) is True
    assert scs._is_pgpass("not a pgpass file", {}) is False


def test_is_authorized_keys():
    body = "ssh-rsa AAAAB3NzaC1yc2EA... user@host\n"
    assert scs._is_authorized_keys(body, {}) is True
    assert scs._is_authorized_keys("random text\n", {}) is False


def test_is_sql_dump():
    assert scs._is_sql_dump("-- MySQL dump 10.13\nCREATE TABLE users (id int);\n", {}) is True
    assert scs._is_sql_dump("CREATE TABLE users (id int); INSERT INTO users VALUES (1);", {}) is True
    assert scs._is_sql_dump("<html>not a dump</html>", {}) is False


def test_is_zip_signature():
    assert scs._is_zip_signature("PK\x03\x04restofzip", {}) is True
    assert scs._is_zip_signature("not a zip", {}) is False


def test_looks_like_binary_archive_requires_content_type_and_garbage():
    headers = {"Content-Type": "application/gzip"}
    body = "\ufffd" * 400
    assert scs._looks_like_binary_archive(body, headers) is True
    assert scs._looks_like_binary_archive("plain readable text " * 20, headers) is False
    assert scs._looks_like_binary_archive("\ufffd" * 400, {"Content-Type": "text/html"}) is False


def test_classify_body_dispatches_to_matching_validator():
    result = scs._classify_body("[core]\nrepositoryformatversion = 0\n", {})
    assert result is not None
    title, severity, cwe = result
    assert "git" in title.lower()
    assert cwe == "CWE-527"


def test_classify_body_returns_none_for_unrecognized_content():
    assert scs._classify_body("just some ordinary text with no signature", {}) is None


def test_derive_hostname_basenames_strips_common_prefixes():
    names = scs._derive_hostname_basenames("api.example.com")
    assert "example" in names
    assert "api" not in names


def test_is_directory_listing_apache_style():
    body = (
        "<html><head><title>Index of /backup</title></head><body>"
        "<h1>Index of /backup</h1>"
        '<a href="../">../</a><a href="dump.sql">dump.sql</a>'
        "</body></html>"
    )
    assert scs._is_directory_listing(body) is True


def test_is_directory_listing_rejects_normal_page():
    body = "<html><head><title>Welcome</title></head><body>Hello</body></html>"
    assert scs._is_directory_listing(body) is False


def test_extract_listing_hrefs_filters_parent_and_cross_host():
    body = (
        '<a href="../">../</a>'
        '<a href="dump.sql">dump.sql</a>'
        '<a href="https://other.com/evil">evil</a>'
        '<a href="?sort=name">sort</a>'
    )
    hrefs = scs._extract_listing_hrefs(body, "https://example.com/backup/")
    assert hrefs == ["https://example.com/backup/dump.sql"]


@pytest.mark.asyncio
async def test_check_finds_git_head_at_root():
    responses = {
        "https://example.com/blfinder_src_canary_ANY_does_not_exist": (404, {}, "not found"),
        "https://example.com/.git/HEAD": (200, {}, "ref: refs/heads/main\n"),
    }

    async def fake_request(method, url, **kwargs):
        if url.startswith("https://example.com/blfinder_src_canary_"):
            return 404, {}, "not found", 0.01
        if url in responses:
            status, headers, body = responses[url]
            return status, headers, body, 0.01
        return 404, {}, "not found", 0.01

    fake = types.SimpleNamespace(config=types.SimpleNamespace(verbose=False), _request=fake_request)
    scanner = scs.SourceCodeScanner(fake)

    findings = await scanner.check("https://example.com/", "GET", 200, {}, "<html>home</html>")
    titles = [f.title for f in findings]
    assert any("HEAD" in t for t in titles)


@pytest.mark.asyncio
async def test_check_suppresses_findings_on_spa_catch_all():
    catch_all_body = "<html>this is the SPA shell for every route</html>"

    async def fake_request(method, url, **kwargs):
        return 200, {}, catch_all_body, 0.01

    fake = types.SimpleNamespace(config=types.SimpleNamespace(verbose=False), _request=fake_request)
    scanner = scs.SourceCodeScanner(fake)

    findings = await scanner.check("https://spa.example.com/", "GET", 200, {}, catch_all_body)
    assert findings == []


@pytest.mark.asyncio
async def test_check_reports_directory_listing_and_classifies_linked_file():
    listing_body = (
        "<html><head><title>Index of /backup/</title></head><body>"
        "<h1>Index of /backup/</h1>"
        '<a href="../">../</a>'
        '<a href="dump.sql">dump.sql</a>'
        "</body></html>"
    )
    dump_body = "-- MySQL dump 10.13\nCREATE TABLE users (id int);\n"

    async def fake_request(method, url, **kwargs):
        if url.startswith("https://example.com/blfinder_src_canary_"):
            return 404, {}, "not found", 0.01
        if url == "https://example.com/backup/dump.sql":
            return 200, {}, dump_body, 0.01
        return 404, {}, "not found", 0.01

    fake = types.SimpleNamespace(config=types.SimpleNamespace(verbose=False), _request=fake_request)
    scanner = scs.SourceCodeScanner(fake)

    findings = await scanner.check("https://example.com/backup/", "GET", 200, {}, listing_body)
    titles = [f.title for f in findings]
    assert any("Directory Listing" in t for t in titles)
    assert any("Archive" in t or "Dump" in t or "Backup" in t for t in titles)


@pytest.mark.asyncio
async def test_check_ignores_unclassified_non_sensitive_listing_entries():
    listing_body = (
        "<html><head><title>Index of /assets/</title></head><body>"
        "<h1>Index of /assets/</h1>"
        '<a href="../">../</a>'
        '<a href="logo.png">logo.png</a>'
        "</body></html>"
    )

    async def fake_request(method, url, **kwargs):
        return 404, {}, "not found", 0.01

    fake = types.SimpleNamespace(config=types.SimpleNamespace(verbose=False), _request=fake_request)
    scanner = scs.SourceCodeScanner(fake)

    findings = await scanner.check("https://example.com/assets/", "GET", 200, {}, listing_body)
    assert any("Directory Listing" in f.title for f in findings)
    assert not any("logo.png" in f.endpoint for f in findings)
