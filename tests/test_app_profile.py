"""AppProfile model: lenient defaults, usability, enum strictness."""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from appsecwatch.models import AppProfile


def test_defaults_are_lenient_and_usable():
    p = AppProfile()
    assert p.audience == "unknown"
    assert p.confidence == "low"
    assert p.expected_controls == []
    assert p.error is None
    assert p.usable is True


def test_errored_profile_not_usable():
    p = AppProfile(host="h", error="LLM timeout")
    assert p.usable is False


def test_partial_json_validates():
    p = AppProfile.model_validate({
        "app_type": "REST API",
        "audience": "partner",
        "confidence": "high",
        "is_api": True,
    })
    assert p.is_api is True
    assert p.handles_auth is False     # default
    assert p.expected_controls == []


def test_bad_audience_triggers_validation_error():
    # An out-of-enum value must fail so the analyzer retries / degrades.
    with pytest.raises(ValidationError):
        AppProfile.model_validate({"audience": "everyone"})


def test_bad_confidence_triggers_validation_error():
    with pytest.raises(ValidationError):
        AppProfile.model_validate({"confidence": "certain"})
