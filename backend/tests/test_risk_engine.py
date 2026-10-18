import pytest
import math
import sys
import os

# Add backend directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from risk_engine import (
    normalize_email,
    email_similarity,
    analyze_email,
    create_device_fingerprint,
    analyze_device,
    analyze_ip,
    analyze_velocity,
    analyze_user_agent,
    calculate_behavior_score,
    build_feature_vector,
    calculate_final_score,
    determine_action,
    FraudMLModel,
)


# ============================================================
# 1. EMAIL INTELLIGENCE TESTS
# ============================================================

def test_normalize_email_standard():
    assert normalize_email("user@example.com") == "user@example.com"
    assert normalize_email("  User@Example.COM ") == "user@example.com"


def test_normalize_email_subaddress_alias():
    assert normalize_email("promo.user+trial1@gmail.com") == "promouser@gmail.com"
    assert normalize_email("alex+promo99@outlook.com") == "alex@outlook.com"


def test_normalize_email_edge_cases():
    assert normalize_email("") == ""
    assert normalize_email(None) == ""
    assert normalize_email(12345) == "12345"
    assert normalize_email("no_at_symbol") == "no_at_symbol"


def test_analyze_email_legitimate():
    score, signals = analyze_email("elena.rostova@globalcorp.org")
    assert score == 0
    assert len(signals) == 0


def test_analyze_email_disposable_domain():
    score, signals = analyze_email("throwaway@tempmail.com")
    assert score >= 30
    types = [s["type"] for s in signals]
    assert "DISPOSABLE_EMAIL" in types


def test_analyze_email_plus_subaddressing():
    score, signals = analyze_email("john+bonus@gmail.com")
    assert score >= 10
    types = [s["type"] for s in signals]
    assert "SUBADDRESS_EMAIL_ALIAS" in types


def test_analyze_email_numeric_heavy():
    score, signals = analyze_email("user837492@domain.com")
    assert score >= 8
    types = [s["type"] for s in signals]
    assert "NUMERIC_EMAIL" in types


def test_analyze_email_repeated_pattern():
    score, signals = analyze_email("baaaart@domain.com")
    assert score >= 5
    types = [s["type"] for s in signals]
    assert "REPEATED_EMAIL_PATTERN" in types


def test_analyze_email_invalid_format():
    score, signals = analyze_email("not-an-email")
    assert score == 25
    assert signals[0]["type"] == "INVALID_EMAIL"

    score_empty, signals_empty = analyze_email("")
    assert score_empty == 25
    assert signals_empty[0]["type"] == "INVALID_EMAIL"


# ============================================================
# 2. DEVICE FINGERPRINTING & REUSE TESTS
# ============================================================

def test_create_device_fingerprint_deterministic():
    data1 = {
        "screen_width": 1920,
        "screen_height": 1080,
        "timezone": "America/New_York",
        "user_agent": "Mozilla/5.0",
        "hardware_concurrency": 8,
        "max_touch_points": 0,
    }
    data2 = dict(data1)
    assert create_device_fingerprint(data1) == create_device_fingerprint(data2)
    assert len(create_device_fingerprint(data1)) == 64  # SHA-256


def test_create_device_fingerprint_empty_input():
    fp = create_device_fingerprint({})
    assert len(fp) == 64
    fp_none = create_device_fingerprint(None)
    assert len(fp_none) == 64


def test_analyze_device_tiers():
    # 0 previous uses
    score, sigs = analyze_device("fp_test", 0)
    assert score == 0 and len(sigs) == 0

    # 1 previous use
    score, sigs = analyze_device("fp_test", 1)
    assert score == 8 and sigs[0]["severity"] == "LOW"

    # 2 previous uses
    score, sigs = analyze_device("fp_test", 2)
    assert score == 15 and sigs[0]["severity"] == "MEDIUM"

    # 3 previous uses
    score, sigs = analyze_device("fp_test", 3)
    assert score == 28 and sigs[0]["severity"] == "HIGH"

    # 5+ previous uses (cluster)
    score, sigs = analyze_device("fp_test", 6)
    assert score == 40
    assert sigs[0]["type"] == "DEVICE_CLUSTER"
    assert sigs[0]["severity"] == "CRITICAL"


def test_analyze_device_missing_fingerprint():
    score, sigs = analyze_device("", 0)
    assert score == 10
    assert sigs[0]["type"] == "MISSING_DEVICE_FINGERPRINT"


# ============================================================
# 3. IP REUSE & VELOCITY TESTS
# ============================================================

def test_analyze_ip_tiers():
    assert analyze_ip("198.51.100.1", 0)[0] == 0
    assert analyze_ip("198.51.100.1", 2)[0] == 8
    assert analyze_ip("198.51.100.1", 3)[0] == 15
    assert analyze_ip("198.51.100.1", 5)[0] == 25

    score_crit, sigs_crit = analyze_ip("198.51.100.1", 9)
    assert score_crit == 35
    assert sigs_crit[0]["type"] == "IP_CLUSTER"


def test_analyze_ip_missing():
    score, sigs = analyze_ip("", 0)
    assert score == 10
    assert sigs[0]["type"] == "MISSING_IP_ADDRESS"


def test_analyze_velocity_tiers():
    assert analyze_velocity(0)[0] == 0
    assert analyze_velocity(1)[0] == 0
    assert analyze_velocity(2)[0] == 10
    assert analyze_velocity(3)[0] == 20
    assert analyze_velocity(4)[0] == 28
    assert analyze_velocity(7)[0] == 35


# ============================================================
# 4. USER AGENT & AUTOMATION TESTS
# ============================================================

def test_analyze_user_agent_clean():
    score, sigs = analyze_user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/122.0.0.0")
    assert score == 0 and len(sigs) == 0


def test_analyze_user_agent_automation():
    headless_ua = "Mozilla/5.0 (X11; Linux x86_64) HeadlessChrome/120.0"
    score, sigs = analyze_user_agent(headless_ua)
    assert score == 30
    assert sigs[0]["type"] == "AUTOMATION_BROWSER"
    assert sigs[0]["severity"] == "CRITICAL"

    playwright_ua = "Mozilla/5.0 Playwright Driver"
    assert analyze_user_agent(playwright_ua)[0] == 30


def test_analyze_user_agent_missing():
    score, sigs = analyze_user_agent("")
    assert score == 10
    assert sigs[0]["type"] == "MISSING_USER_AGENT"


# ============================================================
# 5. BEHAVIORAL BIOMETRICS & BOUNDARY HANDLING
# ============================================================

def test_calculate_behavior_score_human_flow():
    human_data = {
        "form_fill_time": 12.5,
        "mouse_movements": 42,
        "click_count": 4,
        "paste_count": 0,
        "focus_changes": 0,
    }
    score, sigs = calculate_behavior_score(human_data)
    assert score == 0
    assert len(sigs) == 0


def test_calculate_behavior_score_bot_rapid_cadence():
    bot_data = {
        "form_fill_time": 0.9,
        "mouse_movements": 0,
        "click_count": 1,
        "paste_count": 3,
        "focus_changes": 7,
    }
    score, sigs = calculate_behavior_score(bot_data)
    types = [s["type"] for s in sigs]
    assert "FAST_FORM_COMPLETION" in types
    assert "LOW_MOUSE_ACTIVITY" in types
    assert "MULTIPLE_PASTE_EVENTS" in types
    assert "MULTIPLE_FOCUS_CHANGES" in types
    assert "LOW_INTERACTION" in types
    assert score > 40


def test_calculate_behavior_score_invalid_types_and_boundaries():
    # Test strings, None, NaN, and negative numbers
    invalid_data = {
        "form_fill_time": "invalid_fast",
        "mouse_movements": None,
        "click_count": -5,
        "paste_count": "three",
        "focus_changes": float("nan"),
    }
    score, sigs = calculate_behavior_score(invalid_data)
    assert isinstance(score, int)
    assert 0 <= score <= 100

    # Non-dict input
    score_empty, _ = calculate_behavior_score(None)
    assert isinstance(score_empty, int)


# ============================================================
# 6. FEATURE VECTOR CONSTRUCTION
# ============================================================

def test_build_feature_vector_dimension_and_types():
    vec = build_feature_vector(
        device_score=20, email_score=30, ip_score=15, user_agent_score=0,
        velocity_score=10, behavior_score=25, form_fill_time=4.2,
        mouse_movements=18, paste_count=1, focus_changes=2,
        hardware_concurrency=8, max_touch_points=0
    )
    assert len(vec) == 12
    assert all(isinstance(x, float) for x in vec)


def test_build_feature_vector_nan_coercion():
    vec = build_feature_vector(
        device_score=float("nan"),
        form_fill_time=None,
        mouse_movements="invalid"
    )
    assert len(vec) == 12
    assert not math.isnan(vec[0])
    assert vec[6] == 0.0
    assert vec[7] == 0.0


# ============================================================
# 7. FINAL RISK FUSION & CORRELATION BONUSES
# ============================================================

def test_calculate_final_score_weights():
    # 60% rule, 25% behavior, 15% ML
    score = calculate_final_score(
        rule_score=100,
        behavior_score=0,
        ml_score=0,
    )
    assert score == 60

    score_beh = calculate_final_score(
        rule_score=0,
        behavior_score=100,
        ml_score=0,
    )
    assert score_beh == 25


def test_calculate_final_score_correlation_bonuses():
    # Base without correlation
    base = calculate_final_score(rule_score=20, behavior_score=20, ml_score=0)

    # Reused Device + Reused IP adds +10 bonus
    with_corr = calculate_final_score(
        rule_score=20, behavior_score=20, ml_score=0,
        device_accounts=2, ip_accounts=2
    )
    assert with_corr == base + 10


def test_calculate_final_score_clamping():
    assert calculate_final_score(150, 150, 150, device_accounts=10, ip_accounts=10) == 100
    assert calculate_final_score(-20, -50, 0) == 0


# ============================================================
# 8. DECISION ENGINE 5-TIER ACTION MAPPING
# ============================================================

def test_determine_action_all_tiers():
    # Negative and lower clamped boundary
    assert determine_action(-10) == ("ALLOW", "LOW")
    assert determine_action(0) == ("ALLOW", "LOW")
    assert determine_action(29) == ("ALLOW", "LOW")

    # Boundary 29 -> 30: ALLOW -> MONITOR
    assert determine_action(30) == ("MONITOR", "LOW")
    assert determine_action(49) == ("MONITOR", "LOW")

    # Boundary 49 -> 50: MONITOR -> CHALLENGE
    assert determine_action(50) == ("CHALLENGE", "MEDIUM")
    assert determine_action(69) == ("CHALLENGE", "MEDIUM")

    # Boundary 69 -> 70: CHALLENGE -> REVIEW
    assert determine_action(70) == ("REVIEW", "HIGH")
    assert determine_action(84) == ("REVIEW", "HIGH")

    # Boundary 84 -> 85: REVIEW -> BLOCK
    assert determine_action(85) == ("BLOCK", "CRITICAL")
    assert determine_action(100) == ("BLOCK", "CRITICAL")

    # Upper clamped boundary and type coercion
    assert determine_action(150) == ("BLOCK", "CRITICAL")
    assert determine_action("49") == ("MONITOR", "LOW")
    assert determine_action("50") == ("CHALLENGE", "MEDIUM")


# ============================================================
# 9. MACHINE LEARNING MODEL & STATISTICAL FALLBACK
# ============================================================

def test_fraud_ml_model_sparse_data():
    model = FraudMLModel()
    # Training with fewer than 5 rows does not crash
    model.train([])
    score = model.predict([0.0] * 12)
    assert 0 <= score <= 100

    model.train([[1.0] * 12])
    score = model.predict([0.0] * 12)
    assert 0 <= score <= 100


def test_fraud_ml_model_statistical_baseline():
    model = FraudMLModel()
    historical = [[0.0] * 12 for _ in range(10)]
    model.train(historical)
    assert model.baseline_mean is not None

    # Normal vector should have low anomaly score
    normal_score = model.predict([0.0] * 12)
    assert normal_score <= 30

    # Extreme outlier vector should have higher anomaly score
    outlier_score = model.predict([80.0] * 12)
    assert outlier_score > normal_score


def test_fraud_ml_model_isolation_forest_path(monkeypatch):
    from unittest.mock import MagicMock
    import risk_engine

    mock_iso = MagicMock()
    # Simulate fitted isolation forest: prediction = -1 (anomaly), raw decision = -0.25
    mock_iso.predict.return_value = [-1]
    mock_iso.decision_function.return_value = [-0.25]

    monkeypatch.setattr(risk_engine, "SKLEARN_AVAILABLE", True)
    monkeypatch.setattr(risk_engine, "IsolationForest", lambda **kwargs: mock_iso, raising=False)

    model = risk_engine.FraudMLModel()
    historical = [[10.0] * 12 for _ in range(12)]
    model.train(historical)
    assert model.model is not None

    score = model.predict([50.0] * 12)
    # Anomaly prediction (-1) receives baseline floor of 70
    assert score >= 70

