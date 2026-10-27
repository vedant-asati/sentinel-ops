import json
import pytest
from sentinel_ops.agents.synthesizer import format_incident_brief


def test_exported_json_brief_credential_and_secret_leakage():
    """SECURITY VULNERABILITY / CREDENTIAL LEAK:
    `format_incident_brief(state, fmt='json')` serializes the raw evidence and claims lists
    directly into exported JSON (`ev_list = [_ev_dict(e) for e in evidence]`).
    It claims `"raw_payload_retention": "sanitized"` by default, but NEVER invokes
    `scrub_credentials` or `scrub_attributes` on the evidence dictionaries or labels!
    High-value secrets, bearer tokens, passwords, and AWS keys embedded in observations
    leak verbatim into exported incident briefs.
    """
    sensitive_state = {
        "incident_id": "INC-SECURITY-01",
        "target_service": "payment-service",
        "terminal_status": "SUPPORTED_DIAGNOSIS",
        "root_cause_summary": "Payment database pool exhausted.",
        "evidence": [
            {
                "id": "EV-01",
                "backend_source": "prometheus",
                "query_string": "payment_db_pool_active",
                "query_params": {
                    "api_key": "sk-proj-supersecretapikey123456789",
                    "db_conn": "postgres://admin:SuperSecretPass123!@db-internal.prod:5432/main",
                },
                "entity_labels": {
                    "pod": "payment-service-abc",
                    "authorization": "Bearer secret_bearer_token_xyz987654321",
                    "internal_token": "ghp_1234567890abcdefghijklmnopqrstuvwxyz",
                },
                "finding": "Connection refused to database postgres-internal.prod:5432",
                "raw_payload": (
                    "Error: authentication failed for user 'admin' "
                    "AWS_KEY=AKIAIOSFODNN7EXAMPLE "
                    "Private key: -----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0mockkey...\n-----END RSA PRIVATE KEY-----"
                ),
                "status": "SUCCESS",
            }
        ],
        "structured_claims": [
            {
                "claim_id": "CL-01",
                "claim_type": "root_cause",
                "statement": "Payment database pool exhausted on db-internal.prod",
                "supporting_evidence_ids": ["EV-01"],
            }
        ],
    }

    exported_json_str = format_incident_brief(sensitive_state, fmt="json")
    exported_data = json.loads(exported_json_str)

    # 1. Retention metadata must accurately match redacted output
    assert exported_data["raw_payload_retention"] == "sanitized"

    # 2. Evidence fields must have all credentials/secrets scrubbed cleanly
    exported_ev = exported_data["evidence"][0]
    assert "sk-proj-supersecretapikey123456789" not in exported_ev["query_params"]["api_key"]
    assert "SuperSecretPass123!" not in exported_ev["query_params"]["db_conn"]
    assert "secret_bearer_token_xyz987654321" not in exported_ev["entity_labels"]["authorization"]
    assert "ghp_1234567890abcdefghijklmnopqrstuvwxyz" not in exported_ev["entity_labels"]["internal_token"]
    assert "AKIAIOSFODNN7EXAMPLE" not in exported_ev["raw_payload"]
    assert "-----BEGIN RSA PRIVATE KEY-----" not in exported_ev["raw_payload"]


def test_exported_markdown_brief_secret_leakage_in_summary_and_findings():
    """Verify rendered Markdown brief scrubs tokens and DB credentials cleanly."""
    sensitive_state = {
        "incident_id": "INC-SECURITY-02",
        "target_service": "payment-service",
        "terminal_status": "SUPPORTED_DIAGNOSIS",
        "root_cause_summary": "DB pool leak with token Bearer ab+cd/ef==12345 and uri postgres://admin:P@ssword1@10.0.0.5:5432/prod",
        "evidence": [],
    }

    exported_md = format_incident_brief(sensitive_state, fmt="markdown")
    assert "Bearer ab+cd/ef==12345" not in exported_md
    assert "P@ssword1" not in exported_md
    assert "[REDACTED" in exported_md
