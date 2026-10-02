"""Comprehensive test suite for rajlabs-cert-signer:
- PKI operations & X.509 extensions
- Auth & session management
- Intermediate CA lifecycle (import, activate, delete)
- Certificate issuance (1-step generation & REST CSR signing with presets)
- Certificate revocation & CRL generation
- API token lifecycle (create, usage tracking, revoke, restore, delete, bulk)
- Organization profile defaults
- Public routes & installer scripts
"""
import os
import re
import tempfile
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app import auth, config, pki, store, vault


@pytest.fixture(autouse=True)
def test_env(tmp_path, monkeypatch):
    """Set up isolated temp test directory and clean database for every test."""
    test_data = tmp_path / "data"
    test_data.mkdir()
    (test_data / "issued-certs").mkdir()
    (test_data / "crl").mkdir()
    (test_data / "logs").mkdir()

    monkeypatch.setattr(config, "DATA_DIR", test_data)
    monkeypatch.setattr(config, "CERTS_DIR", test_data / "issued-certs")
    monkeypatch.setattr(config, "CRL_DIR", test_data / "crl")
    monkeypatch.setattr(config, "LOGS_DIR", test_data / "logs")
    monkeypatch.setattr(config, "DB_FILE", test_data / "database.json")
    monkeypatch.setattr(config, "ENCRYPTION_KEY", "test-secret-key-32-chars-minimum-len!!")
    monkeypatch.setattr(config, "DATABASE_URL", "")
    monkeypatch.setattr(store, "backend_name", "json")

    # Initialize empty store with hashed password for "admin"
    admin_pw_hash = auth.hash_password("admin-test-pass")
    store.save({
        "serial": 2000,
        "config": {
            "isFirstRun": False,
            "adminUser": "admin",
            "adminPasswordHash": admin_pw_hash,
            "profile": {"orgName": "RajLabs", "country": "IN", "defaultDays": 90}
        },
        "intermediateCAs": [],
        "certificates": [],
        "apiTokens": []
    })


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def auth_headers(client):
    """Logs in as admin and returns authorization header."""
    resp = client.post("/api/auth/login", json={"username": "admin", "password": "admin-test-pass"})
    assert resp.status_code == 200
    token = resp.json()["token"]
    return {"Authorization": f"Bearer {token}"}


def test_build_pki_extension_urls():
    """Verify CRL, OCSP, and CA Issuers URLs are correctly generated."""
    crl_urls, ocsp_urls, ca_issuers = pki.build_pki_extension_urls("int-server", "https://ca.rajlabs.in")
    
    assert "http://crl.rajlabs.in/int-server.crl" in crl_urls
    assert "https://ca.rajlabs.in/crl/int-server.crl" in crl_urls
    assert "https://certs.rajlabs.in/crl/int-server.crl" in crl_urls

    assert "http://ca.rajlabs.in/ocsp" in ocsp_urls
    assert "http://crl.rajlabs.in/ocsp" in ocsp_urls
    assert "https://ca.rajlabs.in/ocsp" in ocsp_urls

    assert "https://ca.rajlabs.in/api/v1/ca/int-server/cert" in ca_issuers
    assert "https://certs.rajlabs.in/api/v1/ca/int-server/cert" in ca_issuers
    assert "https://certs.rajlabs.in/certs/ca-chain.crt" in ca_issuers


def test_pki_onboarding_and_auth_workflow(client, auth_headers):
    """Test login, setup status, PKI generation, and session validation."""
    # 1. Setup status probe
    st = client.get("/api/auth/setup-status")
    assert st.status_code == 200
    assert "adminUser" in st.json()

    # 2. Whoami / me
    me = client.get("/api/auth/me", headers=auth_headers)
    assert me.status_code == 200
    assert me.json()["username"] == "admin"

    # 3. Invalid login rejection
    bad_login = client.post("/api/auth/login", json={"username": "admin", "password": "wrong-password"})
    assert bad_login.status_code == 401
    assert bad_login.json()["code"] == "INVALID_CREDENTIALS"

    # 4. Onboarding generate PKI
    onboard_resp = client.post("/api/auth/onboarding-generate-pki", json={
        "orgName": "RajLabs Enterprise",
        "country": "IN",
        "state": "Karnataka",
        "city": "Bengaluru",
        "keySize": "2048",
        "rootDays": 365,
        "intDays": 365,
        "intermediates": ["int-server", "int-wifi", "int-iot"]
    })
    assert onboard_resp.status_code == 200
    data = onboard_resp.json()
    assert data["success"] is True
    assert "BEGIN RSA PRIVATE KEY" in data["rootKeyPem"] or "BEGIN PRIVATE KEY" in data["rootKeyPem"]
    assert "BEGIN CERTIFICATE" in data["rootCertPem"]
    assert len(data["intermediates"]) == 3

    # 5. Complete setup
    cs = client.post("/api/auth/complete-setup")
    assert cs.status_code == 200
    assert cs.json()["success"] is True

    # 6. Logout
    lo = client.post("/api/auth/logout", headers=auth_headers)
    assert lo.status_code == 200
    assert lo.json()["success"] is True


def test_intermediate_cas_crud_and_activation(client, auth_headers):
    """Test listing CAs, importing new CAs, switching active CA, and delete protection."""
    # Generate initial PKI
    client.post("/api/auth/onboarding-generate-pki", json={
        "orgName": "RajLabs", "keySize": "2048", "intermediates": ["int-server", "int-wifi"]
    })

    # List intermediate CAs
    resp = client.get("/api/admin/intermediate-cas", headers=auth_headers)
    assert resp.status_code == 200
    cas = resp.json()
    assert len(cas) == 2
    server_ca = next(c for c in cas if c["name"] == "int-server")
    wifi_ca = next(c for c in cas if c["name"] == "int-wifi")
    assert server_ca["isActive"] is True
    assert wifi_ca["isActive"] is False

    # Switch active CA to int-wifi
    act_resp = client.post(f"/api/admin/intermediate-cas/{wifi_ca['id']}/activate", headers=auth_headers)
    assert act_resp.status_code == 200
    assert act_resp.json()["code"] == "ACTIVATED"

    # Verify int-wifi is now active
    cas2 = client.get("/api/admin/intermediate-cas", headers=auth_headers).json()
    assert next(c for c in cas2 if c["name"] == "int-wifi")["isActive"] is True
    assert next(c for c in cas2 if c["name"] == "int-server")["isActive"] is False

    # Try to delete active CA (should be rejected)
    del_act = client.delete(f"/api/admin/intermediate-cas/{wifi_ca['id']}", headers=auth_headers)
    assert del_act.status_code == 400
    assert "Cannot delete the active CA" in del_act.json()["error"]

    # Delete standby CA (int-server)
    del_standby = client.delete(f"/api/admin/intermediate-cas/{server_ca['id']}", headers=auth_headers)
    assert del_standby.status_code == 200
    assert del_standby.json()["code"] == "DELETED"


def test_generate_cert_endpoint_and_presets(client, auth_headers):
    """Test 1-step private key + CSR generation and signing via /api/admin/generate-cert."""
    client.post("/api/auth/onboarding-generate-pki", json={
        "orgName": "RajLabs", "keySize": "2048", "intermediates": ["int-server", "int-wifi"]
    })

    # Issue Web Server certificate (90d)
    gen_server = client.post("/api/admin/generate-cert", headers=auth_headers, json={
        "commonName": "api.rajlabs.in",
        "sans": "api.rajlabs.in, *.rajlabs.in",
        "days": 90,
        "purpose": "server"
    })
    assert gen_server.status_code == 200
    res1 = gen_server.json()
    assert res1["success"] is True
    assert "BEGIN RSA PRIVATE KEY" in res1["privateKey"] or "BEGIN PRIVATE KEY" in res1["privateKey"]
    assert "BEGIN CERTIFICATE" in res1["certificate"]
    assert "BEGIN CERTIFICATE" in res1["fullChain"]
    assert res1["caName"] == "int-server"

    # Issue mTLS Client certificate (30d)
    gen_client = client.post("/api/admin/generate-cert", headers=auth_headers, json={
        "commonName": "billing-worker.internal",
        "sans": "billing-worker.internal",
        "days": 30,
        "purpose": "client"
    })
    assert gen_client.status_code == 200
    res2 = gen_client.json()
    assert res2["success"] is True

    # Issue WiFi RADIUS certificate (365d) -> routes to int-wifi
    gen_wifi = client.post("/api/admin/generate-cert", headers=auth_headers, json={
        "commonName": "radius.rajlabs.in",
        "sans": "radius.rajlabs.in",
        "days": 365,
        "purpose": "wifi"
    })
    assert gen_wifi.status_code == 200
    res3 = gen_wifi.json()
    assert res3["success"] is True
    assert res3["caName"] == "int-wifi"

    # Verify certificates listed in inventory
    inv = client.get("/api/admin/certificates", headers=auth_headers)
    assert inv.status_code == 200
    certs_list = inv.json()
    assert len(certs_list) == 3


def test_rest_sign_api_with_purpose_routing(client, auth_headers):
    """Test REST /api/v1/sign with CSR and inspect X.509 extensions."""
    client.post("/api/auth/onboarding-generate-pki", json={
        "orgName": "RajLabs", "keySize": "2048", "intermediates": ["int-server", "int-wifi", "int-iot"]
    })

    # Create temporary CSR using OpenSSL
    op = "test_csr_sign"
    key_f = str(pki.TMP / f"{op}.key")
    csr_f = str(pki.TMP / f"{op}.csr")
    try:
        pki.run("genrsa", "-out", key_f, "2048")
        pki.run("req", "-new", "-key", key_f, "-out", csr_f, "-subj", "/CN=sensor-01.iot.rajlabs.in")
        with open(csr_f, encoding="utf-8") as f:
            csr_pem = f.read()

        # Sign via REST API routed to IoT
        sign_resp = client.post("/api/v1/sign", headers=auth_headers, json={
            "csr": csr_pem,
            "san": ["sensor-01.iot.rajlabs.in", "gateway.iot.rajlabs.in"],
            "days": 730,
            "purpose": "iot"
        })
        assert sign_resp.status_code == 200
        d = sign_resp.json()
        assert d["success"] is True
        assert d["caName"] == "int-iot"
        assert "BEGIN CERTIFICATE" in d["certificate"]

        # Inspect certificate extensions
        cert_f = str(pki.TMP / f"{op}.crt")
        try:
            with open(cert_f, "w", encoding="utf-8") as f:
                f.write(d["certificate"])
            cert_text = pki.run("x509", "-in", cert_f, "-noout", "-text")

            assert "X509v3 CRL Distribution Points" in cert_text
            assert "int-iot.crl" in cert_text
            assert "Authority Information Access" in cert_text
            assert "DNS:sensor-01.iot.rajlabs.in" in cert_text
            assert "DNS:gateway.iot.rajlabs.in" in cert_text
        finally:
            pki._clean(cert_f)
    finally:
        pki._clean(key_f, csr_f)


def test_certificate_revocation_and_crl(client, auth_headers):
    """Test certificate revocation, bulk revocation, and CRL generation."""
    client.post("/api/auth/onboarding-generate-pki", json={
        "orgName": "RajLabs", "keySize": "2048", "intermediates": ["int-server"]
    })

    # Issue 2 certificates
    c1 = client.post("/api/admin/generate-cert", headers=auth_headers, json={
        "commonName": "host1.rajlabs.in", "days": 90
    }).json()
    c2 = client.post("/api/admin/generate-cert", headers=auth_headers, json={
        "commonName": "host2.rajlabs.in", "days": 90
    }).json()

    # Revoke single certificate
    rev1 = client.post("/api/v1/revoke", headers=auth_headers, json={
        "serial": c1["serial"],
        "reason": "keyCompromise"
    })
    assert rev1.status_code == 200
    assert rev1.json()["code"] == "REVOKED"
    assert rev1.json()["crlRegenerated"] is True

    # Revoking already revoked certificate
    rev_again = client.post("/api/v1/revoke", headers=auth_headers, json={
        "serial": c1["serial"]
    })
    assert rev_again.status_code == 200
    assert rev_again.json()["code"] == "ALREADY_REVOKED"

    # Bulk revoke second certificate
    bulk_rev = client.post("/api/v1/revoke-bulk", headers=auth_headers, json={
        "serials": [c2["serial"]],
        "reason": "superseded"
    })
    assert bulk_rev.status_code == 200
    assert bulk_rev.json()["success"] is True

    # DELETE endpoint revokes + regenerates CRL (RESTful alias of POST /revoke)
    c3 = client.post("/api/admin/generate-cert", headers=auth_headers, json={
        "commonName": "host3.rajlabs.in", "days": 90
    }).json()
    del1 = client.delete(f"/api/v1/certificates/{c3['serial']}?reason=keyCompromise",
                         headers=auth_headers)
    assert del1.status_code == 200
    assert del1.json()["code"] == "REVOKED"
    assert del1.json()["crlRegenerated"] is True

    # DELETE is idempotent — second call reports ALREADY_REVOKED
    del_again = client.delete(f"/api/admin/certificates/{c3['serial']}",
                              headers=auth_headers)
    assert del_again.status_code == 200
    assert del_again.json()["code"] == "ALREADY_REVOKED"

    # DELETE unknown serial → 404, DELETE garbage serial → 400
    del_missing = client.delete("/api/v1/certificates/00deadbeef", headers=auth_headers)
    assert del_missing.status_code == 404
    del_bad = client.delete("/api/v1/certificates/!!!", headers=auth_headers)
    assert del_bad.status_code == 400

    # Download CRL and verify
    crl_resp = client.get("/crl/int-server.crl")
    assert crl_resp.status_code == 200
    assert crl_resp.headers["Content-Type"] == "application/pkix-crl"
    assert len(crl_resp.content) > 0


def test_api_tokens_lifecycle_and_usage(client, auth_headers):
    """Test creating API tokens, x-api-key authentication, usage tracking, revoke/restore/delete."""
    client.post("/api/auth/onboarding-generate-pki", json={
        "orgName": "RajLabs", "keySize": "2048", "intermediates": ["int-server"]
    })

    # 1. Create API token
    create_tok = client.post("/api/admin/tokens", headers=auth_headers, json={
        "name": "Traefik CI Deployer",
        "scopes": ["sign", "revoke"],
        "expiresAt": None
    })
    assert create_tok.status_code == 200
    tok_data = create_tok.json()["token"]
    raw_secret = tok_data["token"]
    token_id = tok_data["id"]
    assert raw_secret.startswith("cert_")

    # 2. Use API token via x-api-key header to sign CSR
    op = "test_token_csr"
    key_f = str(pki.TMP / f"{op}.key")
    csr_f = str(pki.TMP / f"{op}.csr")
    try:
        pki.run("genrsa", "-out", key_f, "2048")
        pki.run("req", "-new", "-key", key_f, "-out", csr_f, "-subj", "/CN=traefik.rajlabs.in")
        with open(csr_f, encoding="utf-8") as f:
            csr_pem = f.read()

        sign_with_key = client.post("/api/v1/sign", headers={"x-api-key": raw_secret}, json={
            "csr": csr_pem,
            "san": ["traefik.rajlabs.in"],
            "days": 60
        })
        assert sign_with_key.status_code == 200
        assert sign_with_key.json()["success"] is True

        # 3. Check token usage tracking
        usage = client.get(f"/api/admin/tokens/{token_id}/usage", headers=auth_headers)
        assert usage.status_code == 200
        u_data = usage.json()
        assert u_data["token"]["usageCount"] >= 1
        assert len(u_data["certificates"]) == 1
        assert u_data["certificates"][0]["commonName"] == "traefik.rajlabs.in"

        # 4. Revoke token
        rev_tok = client.post(f"/api/admin/tokens/{token_id}/revoke", headers=auth_headers)
        assert rev_tok.status_code == 200
        assert rev_tok.json()["token"]["status"] == "revoked"

        # 5. Calling API with revoked token must return 401 UNAUTHORIZED
        sign_blocked = client.post("/api/v1/sign", headers={"x-api-key": raw_secret}, json={
            "csr": csr_pem,
            "days": 60
        })
        assert sign_blocked.status_code == 401
        assert sign_blocked.json()["code"] == "UNAUTHORIZED"

        # 6. Restore token
        rest_tok = client.post(f"/api/admin/tokens/{token_id}/restore", headers=auth_headers)
        assert rest_tok.status_code == 200
        assert rest_tok.json()["token"]["status"] == "active"

        # 7. Calling API with restored token must succeed
        sign_restored = client.post("/api/v1/sign", headers={"x-api-key": raw_secret}, json={
            "csr": csr_pem,
            "days": 60
        })
        assert sign_restored.status_code == 200

        # 8. Delete token
        del_tok = client.delete(f"/api/admin/tokens/{token_id}", headers=auth_headers)
        assert del_tok.status_code == 200
        assert del_tok.json()["success"] is True
    finally:
        pki._clean(key_f, csr_f)


def test_org_profile_and_settings(client, auth_headers):
    """Test getting and updating organization profile defaults."""
    # Fetch profile defaults
    prof = client.get("/api/admin/profile", headers=auth_headers)
    assert prof.status_code == 200
    assert prof.json()["orgName"] == "RajLabs"

    # Save new profile defaults
    save_prof = client.post("/api/admin/profile", headers=auth_headers, json={
        "orgName": "RajLabs Global Infrastructure",
        "domainSuffix": "rajlabs.corp",
        "country": "US",
        "state": "California",
        "city": "San Francisco",
        "defaultDays": 180
    })
    assert save_prof.status_code == 200
    assert save_prof.json()["success"] is True

    # Verify updated values
    prof2 = client.get("/api/admin/profile", headers=auth_headers).json()
    assert prof2["orgName"] == "RajLabs Global Infrastructure"
    assert prof2["defaultDays"] == 180


def test_public_routes_and_installers(client):
    """Test public trust downloads, ACME endpoints, and installer scripts."""
    client.post("/api/auth/onboarding-generate-pki", json={
        "orgName": "RajLabs", "keySize": "2048", "intermediates": ["int-server"]
    })

    # Health check
    h = client.get("/health")
    assert h.status_code == 200
    assert h.json()["status"] == "ok"

    # Status check
    st = client.get("/api/v1/status")
    assert st.status_code == 200
    assert st.json()["activeCA"] == "int-server"

    # Root CA download
    rc = client.get("/certs/root-ca.crt")
    assert rc.status_code == 200
    assert "BEGIN CERTIFICATE" in rc.text

    # Intermediate CA download
    ic = client.get("/certs/intermediate-ca.crt")
    assert ic.status_code == 200
    assert "BEGIN CERTIFICATE" in ic.text

    # CA chain download
    chain = client.get("/certs/ca-chain.crt")
    assert chain.status_code == 200
    assert "BEGIN CERTIFICATE" in chain.text

    # Windows trust installer script
    ps1 = client.get("/install-trust-windows.ps1")
    assert ps1.status_code == 200
    assert "X509Store" in ps1.text or "Enterprise Trust Chain" in ps1.text

    # Linux trust installer script
    sh = client.get("/install-trust-linux.sh")
    assert sh.status_code == 200
    assert "update-ca-certificates" in sh.text or "trust anchor" in sh.text

    # ACME Directory endpoint
    acme = client.get("/acme/directory")
    assert acme.status_code == 200
    assert "newNonce" in acme.json()
