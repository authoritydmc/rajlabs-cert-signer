"""Comprehensive test suite for rajlabs-cert-signer PKI operations, extensions, CRL & AIA URLs."""
import os
import re
import tempfile
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app import config, pki, store, vault


@pytest.fixture(autouse=True)
def test_env(tmp_path, monkeypatch):
    """Set up isolated temp test directory and database."""
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

    # Initialize empty store
    store.save({
        "serial": 2000,
        "config": {"isFirstRun": False, "adminUser": "admin", "adminPasswordHash": ""},
        "intermediateCAs": [],
        "certificates": [],
        "apiTokens": []
    })


@pytest.fixture
def client():
    return TestClient(app)


def test_build_pki_extension_urls():
    """Verify CRL, OCSP, and CA Issuers URLs are correctly generated."""
    crl_urls, ocsp_urls, ca_issuers = pki.build_pki_extension_urls("int-server", "https://ca.rajlabs.in")
    
    # Assert CRL URLs contains http and https endpoints for crl.rajlabs.in and ca.rajlabs.in
    assert "http://crl.rajlabs.in/int-server.crl" in crl_urls
    assert "https://ca.rajlabs.in/crl/int-server.crl" in crl_urls
    assert "https://certs.rajlabs.in/crl/int-server.crl" in crl_urls

    # Assert OCSP URLs
    assert "http://ca.rajlabs.in/ocsp" in ocsp_urls
    assert "http://crl.rajlabs.in/ocsp" in ocsp_urls
    assert "https://ca.rajlabs.in/ocsp" in ocsp_urls

    # Assert CA Issuers URLs
    assert "https://ca.rajlabs.in/api/v1/ca/int-server/cert" in ca_issuers
    assert "https://certs.rajlabs.in/api/v1/ca/int-server/cert" in ca_issuers
    assert "https://certs.rajlabs.in/certs/ca-chain.crt" in ca_issuers


def test_pki_generation_and_certificate_signing(client):
    """Generate PKI hierarchy, sign leaf cert, and verify X.509 extensions."""
    # 1. Generate PKI via onboarding endpoint
    resp = client.post("/api/auth/onboarding-generate-pki", json={
        "orgName": "RajLabs",
        "country": "IN",
        "state": "Karnataka",
        "city": "Bengaluru",
        "keySize": "2048",
        "rootDays": 365,
        "intDays": 365,
        "intermediates": ["int-server", "int-wifi"]
    })
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["success"] is True
    assert len(data["intermediates"]) == 2

    # 2. Generate a client CSR using OpenSSL
    op = "test_csr"
    key_f = str(pki.TMP / f"{op}.key")
    csr_f = str(pki.TMP / f"{op}.csr")
    try:
        pki.run("genrsa", "-out", key_f, "2048")
        pki.run("req", "-new", "-key", key_f, "-out", csr_f, "-subj", "/CN=wifi.rajlabs.in")
        with open(csr_f, encoding="utf-8") as f:
            csr_pem = f.read()

        # 3. Sign the certificate via sign_leaf
        result = pki.sign_leaf(
            csr_pem=csr_pem,
            san_domains=["wifi.rajlabs.in", "backend.rajlabs.in"],
            days=90,
            issued_via={"id": "test", "name": "pytest"},
            public_base="https://backend.rajlabs.in/cert-signer",
            ca_hint={"ca": "int-server"}
        )

        assert result["certId"]
        assert result["serial"]
        assert "BEGIN CERTIFICATE" in result["certificate"]
        assert "BEGIN CERTIFICATE" in result["fullChain"]

        # 4. Inspect signed certificate with OpenSSL to verify CRL & AIA extensions
        cert_path = config.CERTS_DIR / f"{result['certId']}.crt"
        assert cert_path.exists()

        cert_text = pki.run("x509", "-in", str(cert_path), "-noout", "-text")
        
        # Verify CRL Distribution Points in the cert
        assert "X509v3 CRL Distribution Points" in cert_text
        assert "http://crl.rajlabs.in/int-server.crl" in cert_text
        assert "https://ca.rajlabs.in/crl/int-server.crl" in cert_text

        # Verify Authority Information Access in the cert
        assert "Authority Information Access" in cert_text
        assert "OCSP - URI:http://ca.rajlabs.in/ocsp" in cert_text
        assert "CA Issuers - URI:https://ca.rajlabs.in/api/v1/ca/int-server/cert" in cert_text

        # Verify SANs
        assert "DNS:wifi.rajlabs.in" in cert_text
        assert "DNS:backend.rajlabs.in" in cert_text

    finally:
        pki._clean(key_f, csr_f)


def test_public_routes(client):
    """Test public trust endpoints, health, and CRL aliases."""
    # Generate PKI first
    client.post("/api/auth/onboarding-generate-pki", json={
        "orgName": "RajLabs",
        "keySize": "2048",
        "intermediates": ["int-server"]
    })

    # Health check
    h = client.get("/health")
    assert h.status_code == 200
    assert h.json()["status"] == "ok"

    # Status check
    st = client.get("/api/v1/status")
    assert st.status_code == 200
    assert st.json()["activeCA"] == "int-server"

    # Root cert download
    rc = client.get("/certs/root-ca.crt")
    assert rc.status_code == 200
    assert "BEGIN CERTIFICATE" in rc.text

    # CA chain download & aliases
    chain = client.get("/certs/ca-chain.crt")
    assert chain.status_code == 200
    assert "BEGIN CERTIFICATE" in chain.text

    ca_alias = client.get("/ca.pem")
    assert ca_alias.status_code == 200
    assert ca_alias.text == chain.text

    # OCSP endpoint
    ocsp = client.get("/ocsp")
    assert ocsp.status_code == 200
    assert b"Rajlabs OCSP Responder" in ocsp.content
