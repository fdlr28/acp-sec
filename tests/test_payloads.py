"""Tests for the injection payload library."""

import pytest

from acpsec.injection.payloads import (
    ALL_PAYLOADS,
    CATEGORIES,
    DIRECT_OVERRIDE,
    ENCODED_INJECTION,
    EXTRACTION_PROBES,
    INDIRECT_INJECTION,
    MULTITURN_INJECTION,
    ROLE_CONFUSION,
    Payload,
)


class TestPayloadLibrary:
    def test_all_payloads_non_empty(self):
        assert len(ALL_PAYLOADS) > 0

    def test_all_payloads_have_unique_ids(self):
        ids = [p.test_id for p in ALL_PAYLOADS]
        assert len(ids) == len(set(ids)), "Duplicate test_id found"

    def test_all_payloads_have_category(self):
        for p in ALL_PAYLOADS:
            assert p.category, f"Payload {p.test_id} missing category"

    def test_all_payloads_have_text(self):
        for p in ALL_PAYLOADS:
            assert p.text.strip(), f"Payload {p.test_id} has empty text"

    def test_categories_match_all_payloads(self):
        all_from_cats = [p for cat in CATEGORIES.values() for p in cat]
        assert len(all_from_cats) == len(ALL_PAYLOADS)

    def test_direct_override_count(self):
        assert len(DIRECT_OVERRIDE) >= 5

    def test_role_confusion_count(self):
        assert len(ROLE_CONFUSION) >= 5

    def test_encoded_injection_count(self):
        assert len(ENCODED_INJECTION) >= 5

    def test_extraction_probes_count(self):
        assert len(EXTRACTION_PROBES) >= 5

    def test_payload_decode_plain(self):
        p = Payload(test_id="X-01", category="test", name="Test", text="Hello", encoding="plain")
        assert p.decode() == "Hello"

    def test_payload_decode_rot13(self):
        p = Payload(test_id="X-02", category="test", name="Test", text="Uryyb", encoding="rot13")
        assert p.decode() == "Hello"
