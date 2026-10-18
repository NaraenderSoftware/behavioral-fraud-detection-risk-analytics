import hashlib
import math
import re

# Graceful import of scikit-learn IsolationForest
try:
    from sklearn.ensemble import IsolationForest
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False


# =========================================================
# HELPER FUNCTIONS FOR ROBUST TYPE COERCION & VALIDATION
# =========================================================

def _safe_float(val, default=0.0):
    try:
        if val is None:
            return default
        f = float(val)
        return default if (math.isnan(f) or math.isinf(f)) else f
    except (ValueError, TypeError):
        return default


def _safe_int(val, default=0):
    try:
        if val is None:
            return default
        return int(val)
    except (ValueError, TypeError):
        return default


def _safe_str(val, default=""):
    if val is None:
        return default
    return str(val)


# =========================================================
# CONFIGURATION
# =========================================================

DISPOSABLE_DOMAINS = {
    "tempmail.com",
    "10minutemail.com",
    "guerrillamail.com",
    "guerrillamail.biz",
    "mailinator.com",
    "yopmail.com",
    "temp-mail.org",
    "throwawaymail.com",
    "maildrop.cc",
    "sharklasers.com",
    "dispostable.com",
    "trashmail.com",
    "getnada.com",
    "nada.ltd",
    "fakeinbox.com",
    "inboxbear.com",
    "crazymailing.com",
}


# =========================================================
# EMAIL INTELLIGENCE
# =========================================================

def normalize_email(email):
    """
    Return a canonical normalized representation of an email address.
    Removes '+alias' tags and strips dots from Gmail addresses to detect
    subaddressing and alias reuse.
    """
    email = _safe_str(email).strip().lower()

    if "@" not in email:
        return email

    parts = email.split("@", 1)
    if len(parts) != 2:
        return email
    local, domain = parts

    # Remove +aliases (e.g. john+promo@gmail.com -> john@gmail.com)
    local = local.split("+")[0]

    # For Gmail, periods do not distinguish distinct inboxes
    if domain in ("gmail.com", "googlemail.com"):
        local = local.replace(".", "")

    return f"{local}@{domain}"


def email_similarity(email_a, email_b):
    """
    Calculate similarity score between two email addresses (0.0 to 1.0).
    Uses character set overlap for matching local names.
    """
    a = normalize_email(email_a)
    b = normalize_email(email_b)

    if not a or not b:
        return 0.0

    if a == b:
        return 1.0

    try:
        local_a, domain_a = a.split("@")
        local_b, domain_b = b.split("@")
    except ValueError:
        return 0.0

    if domain_a != domain_b:
        return 0.0

    set_a = set(local_a)
    set_b = set(local_b)
    union = set_a | set_b

    if not union:
        return 0.0

    return len(set_a & set_b) / len(union)


def analyze_email(email):
    """
    Analyze email string for disposable domains, alias subaddressing,
    suspicious character patterns, and numeric density.
    """
    signals = []
    score = 0

    email = _safe_str(email).strip().lower()

    # 1. Format & Length Validation
    if not email or len(email) > 254 or not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
        return 25, [{
            "type": "INVALID_EMAIL",
            "severity": "HIGH",
            "points": 25,
            "message": "Invalid email format"
        }]

    parts = email.split("@", 1)
    if len(parts) != 2:
        return 25, [{
            "type": "INVALID_EMAIL",
            "severity": "HIGH",
            "points": 25,
            "message": "Invalid email format"
        }]
    local_part, domain = parts

    # 2. Disposable Email Detection
    if domain in DISPOSABLE_DOMAINS:
        score += 30
        signals.append({
            "type": "DISPOSABLE_EMAIL",
            "severity": "HIGH",
            "points": 30,
            "message": f"Disposable email domain detected ({domain})"
        })

    # 3. Subaddressing (+ alias abuse detection)
    if "+" in local_part:
        score += 10
        signals.append({
            "type": "SUBADDRESS_EMAIL_ALIAS",
            "severity": "MEDIUM",
            "points": 10,
            "message": "Email uses plus-addressing (+ alias) commonly used in promo abuse"
        })

    # 4. Numeric-Heavy Email
    digit_count = sum(c.isdigit() for c in local_part)
    if digit_count >= 5:
        score += 8
        signals.append({
            "type": "NUMERIC_EMAIL",
            "severity": "MEDIUM",
            "points": 8,
            "message": "Email contains unusually high number of digits"
        })

    # 5. Repeated Character Pattern
    if re.search(r"(.)\1\1", local_part):
        score += 5
        signals.append({
            "type": "REPEATED_EMAIL_PATTERN",
            "severity": "LOW",
            "points": 5,
            "message": "Repeated-character email pattern detected"
        })

    return score, signals


# =========================================================
# DEVICE FINGERPRINTING
# =========================================================

def create_device_fingerprint(data):
    """
    Generate SHA-256 fingerprint hash from device hardware & environment attributes.
    """
    if not isinstance(data, dict):
        data = {}

    raw = "|".join([
        _safe_str(data.get("screen_width", "")),
        _safe_str(data.get("screen_height", "")),
        _safe_str(data.get("timezone", "")),
        _safe_str(data.get("user_agent", "")),
        _safe_str(data.get("hardware_concurrency", "")),
        _safe_str(data.get("max_touch_points", "")),
    ])

    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


# =========================================================
# DEVICE ANALYSIS
# =========================================================

def analyze_device(device_fingerprint, existing_count):
    signals = []
    score = 0
    existing_count = max(0, _safe_int(existing_count))
    device_fingerprint = _safe_str(device_fingerprint).strip()

    if not device_fingerprint:
        return 10, [{
            "type": "MISSING_DEVICE_FINGERPRINT",
            "severity": "MEDIUM",
            "points": 10,
            "message": "Device fingerprint is missing"
        }]

    if existing_count >= 5:
        score = 40
        signals.append({
            "type": "DEVICE_CLUSTER",
            "severity": "CRITICAL",
            "points": 40,
            "message": f"Device already associated with {existing_count} accounts"
        })
    elif existing_count >= 3:
        score = 28
        signals.append({
            "type": "DEVICE_REUSE",
            "severity": "HIGH",
            "points": 28,
            "message": f"Device already associated with {existing_count} accounts"
        })
    elif existing_count >= 2:
        score = 15
        signals.append({
            "type": "DEVICE_REUSE",
            "severity": "MEDIUM",
            "points": 15,
            "message": f"Device already associated with {existing_count} accounts"
        })
    elif existing_count >= 1:
        score = 8
        signals.append({
            "type": "DEVICE_REUSE",
            "severity": "LOW",
            "points": 8,
            "message": "Device has been used by another account"
        })

    return score, signals


# =========================================================
# IP ANALYSIS
# =========================================================

def analyze_ip(ip, existing_count):
    signals = []
    score = 0
    existing_count = max(0, _safe_int(existing_count))
    ip = _safe_str(ip).strip()

    if not ip:
        return 10, [{
            "type": "MISSING_IP_ADDRESS",
            "severity": "MEDIUM",
            "points": 10,
            "message": "Client IP address is missing"
        }]

    if existing_count >= 8:
        score = 35
        signals.append({
            "type": "IP_CLUSTER",
            "severity": "CRITICAL",
            "points": 35,
            "message": f"IP address associated with {existing_count} accounts"
        })
    elif existing_count >= 5:
        score = 25
        signals.append({
            "type": "IP_REUSE",
            "severity": "HIGH",
            "points": 25,
            "message": f"IP address associated with {existing_count} accounts"
        })
    elif existing_count >= 3:
        score = 15
        signals.append({
            "type": "IP_REUSE",
            "severity": "MEDIUM",
            "points": 15,
            "message": "Multiple accounts detected from same IP"
        })
    elif existing_count >= 2:
        score = 8
        signals.append({
            "type": "IP_REUSE",
            "severity": "LOW",
            "points": 8,
            "message": "IP address has been used by another account"
        })

    return score, signals


# =========================================================
# VELOCITY ANALYSIS
# =========================================================

def analyze_velocity(recent_count):
    signals = []
    score = 0
    recent_count = max(0, _safe_int(recent_count))

    if recent_count >= 6:
        score = 35
        signals.append({
            "type": "HIGH_VELOCITY",
            "severity": "CRITICAL",
            "points": 35,
            "message": f"{recent_count} signup attempts within 5 minutes"
        })
    elif recent_count >= 4:
        score = 28
        signals.append({
            "type": "HIGH_VELOCITY",
            "severity": "HIGH",
            "points": 28,
            "message": f"{recent_count} signup attempts within 5 minutes"
        })
    elif recent_count >= 3:
        score = 20
        signals.append({
            "type": "HIGH_VELOCITY",
            "severity": "HIGH",
            "points": 20,
            "message": f"{recent_count} signup attempts within 5 minutes"
        })
    elif recent_count >= 2:
        score = 10
        signals.append({
            "type": "SIGNUP_VELOCITY",
            "severity": "MEDIUM",
            "points": 10,
            "message": "Repeated signup activity detected in short window"
        })

    return score, signals


# =========================================================
# USER AGENT / AUTOMATION ANALYSIS
# =========================================================

def analyze_user_agent(user_agent):
    signals = []
    score = 0
    user_agent = _safe_str(user_agent).strip()

    if not user_agent:
        return 10, [{
            "type": "MISSING_USER_AGENT",
            "severity": "MEDIUM",
            "points": 10,
            "message": "Browser user-agent is missing"
        }]

    suspicious_terms = [
        "headless",
        "phantomjs",
        "selenium",
        "playwright",
        "puppeteer",
        "webdriver",
    ]

    lowered = user_agent.lower()
    detected = [term for term in suspicious_terms if term in lowered]

    if detected:
        score = 30
        signals.append({
            "type": "AUTOMATION_BROWSER",
            "severity": "CRITICAL",
            "points": 30,
            "message": f"Automated browser environment detected ({', '.join(detected)})"
        })

    return score, signals


# =========================================================
# BEHAVIOR ANALYSIS
# =========================================================

def calculate_behavior_score(data):
    """
    Evaluates client-side behavioral telemetry during the signup session:
    Form completion speed, mouse dynamics, clipboard paste count, and focus switching.
    """
    signals = []
    score = 0

    if not isinstance(data, dict):
        data = {}

    form_fill_time = max(0.0, _safe_float(data.get("form_fill_time", 0)))
    mouse_movements = max(0, _safe_int(data.get("mouse_movements", 0)))
    click_count = max(0, _safe_int(data.get("click_count", 0)))
    paste_count = max(0, _safe_int(data.get("paste_count", 0)))
    focus_changes = max(0, _safe_int(data.get("focus_changes", 0)))

    # 1. Unnatural Form Completion Speed
    if 0 < form_fill_time < 2.5:
        score += 15
        signals.append({
            "type": "FAST_FORM_COMPLETION",
            "severity": "HIGH",
            "points": 15,
            "message": f"Form completed unnaturally fast ({form_fill_time:.1f} seconds)"
        })
    elif 0 < form_fill_time < 5.0:
        score += 5
        signals.append({
            "type": "FAST_FORM_COMPLETION",
            "severity": "LOW",
            "points": 5,
            "message": f"Form completed quickly ({form_fill_time:.1f} seconds)"
        })

    # 2. Mouse Dynamics
    if mouse_movements <= 2:
        score += 12
        signals.append({
            "type": "LOW_MOUSE_ACTIVITY",
            "severity": "MEDIUM",
            "points": 12,
            "message": "Minimal or zero mouse cursor movement detected"
        })

    # 3. Paste Activity
    if paste_count >= 3:
        score += 15
        signals.append({
            "type": "MULTIPLE_PASTE_EVENTS",
            "severity": "HIGH",
            "points": 15,
            "message": f"Heavy clipboard paste activity detected ({paste_count} paste events)"
        })
    elif paste_count >= 2:
        score += 10
        signals.append({
            "type": "MULTIPLE_PASTE_EVENTS",
            "severity": "MEDIUM",
            "points": 10,
            "message": f"Multiple paste events detected ({paste_count} paste events)"
        })

    # 4. Focus Changes
    if focus_changes >= 6:
        score += 12
        signals.append({
            "type": "MULTIPLE_FOCUS_CHANGES",
            "severity": "HIGH",
            "points": 12,
            "message": "Unusual page tab switching / visibility changes detected"
        })
    elif focus_changes >= 3:
        score += 8
        signals.append({
            "type": "MULTIPLE_FOCUS_CHANGES",
            "severity": "MEDIUM",
            "points": 8,
            "message": "Repeated tab visibility changes detected"
        })

    # 5. Low Overall Interaction
    if click_count <= 1 and mouse_movements <= 2:
        score += 5
        signals.append({
            "type": "LOW_INTERACTION",
            "severity": "LOW",
            "points": 5,
            "message": "Abnormally low human interaction recorded during signup"
        })

    return min(score, 100), signals


# =========================================================
# FEATURE VECTOR FOR ML
# =========================================================

def build_feature_vector(
    device_score=0,
    email_score=0,
    ip_score=0,
    user_agent_score=0,
    velocity_score=0,
    behavior_score=0,
    form_fill_time=0,
    mouse_movements=0,
    paste_count=0,
    focus_changes=0,
    hardware_concurrency=0,
    max_touch_points=0,
):
    """
    Constructs the canonical 12-dimensional numerical feature vector
    for machine learning anomaly detection.
    """
    return [
        _safe_float(device_score),
        _safe_float(email_score),
        _safe_float(ip_score),
        _safe_float(user_agent_score),
        _safe_float(velocity_score),
        _safe_float(behavior_score),
        _safe_float(form_fill_time),
        _safe_float(mouse_movements),
        _safe_float(paste_count),
        _safe_float(focus_changes),
        _safe_float(hardware_concurrency),
        _safe_float(max_touch_points),
    ]


# =========================================================
# FINAL RISK FUSION
# =========================================================

def calculate_final_score(
    rule_score,
    behavior_score,
    ml_score,
    device_accounts=0,
    ip_accounts=0,
    recent_signups=0,
    signal_count=0,
):
    """
    Fuse independent detection engines into a unified 0-100 composite risk score.
    Weights: 60% deterministic rules, 25% behavioral telemetry, 15% ML anomaly score.
    Applies multi-signal correlation bonuses when multiple independent dimensions agree.
    """
    rule_score = max(0.0, min(100.0, _safe_float(rule_score)))
    behavior_score = max(0.0, min(100.0, _safe_float(behavior_score)))
    ml_score = max(0.0, min(100.0, _safe_float(ml_score)))
    device_accounts = max(0, _safe_int(device_accounts))
    ip_accounts = max(0, _safe_int(ip_accounts))
    recent_signups = max(0, _safe_int(recent_signups))
    signal_count = max(0, _safe_int(signal_count))

    base_score = (
        rule_score * 0.60
        + behavior_score * 0.25
        + ml_score * 0.15
    )

    bonus = 0

    # Strong correlation: Reused Device + Reused IP
    if device_accounts >= 2 and ip_accounts >= 2:
        bonus += 10

    # Coordinated velocity from reused device
    if recent_signups >= 2 and device_accounts >= 2:
        bonus += 8

    # Suspicious behavior combined with identity reuse
    if behavior_score >= 30 and (device_accounts >= 2 or ip_accounts >= 3):
        bonus += 8

    # High velocity combined with infrastructure reuse
    if recent_signups >= 3 and (device_accounts >= 2 or ip_accounts >= 3):
        bonus += 10

    # Multi-signal accumulation bonus
    if signal_count >= 5:
        bonus += 5

    total = base_score + bonus
    return int(max(0, min(100, round(total))))


# =========================================================
# DECISION ENGINE (5-TIER GRADUATED RESPONSE)
# =========================================================

def determine_action(score):
    """
    Maps 0-100 score to graduated action tier and risk severity.
    Tiers:
      ALLOW (0-29, LOW)
      MONITOR (30-49, LOW)
      CHALLENGE (50-69, MEDIUM)
      REVIEW (70-84, HIGH)
      BLOCK (85-100, CRITICAL)
    """
    s = max(0, min(100, _safe_int(score)))
    if s >= 85:
        return "BLOCK", "CRITICAL"
    if s >= 70:
        return "REVIEW", "HIGH"
    if s >= 50:
        return "CHALLENGE", "MEDIUM"
    if s >= 30:
        return "MONITOR", "LOW"
    return "ALLOW", "LOW"


# =========================================================
# ML ANOMALY MODEL (ISOLATION FOREST WITH HEURISTIC FALLBACK)
# =========================================================

class FraudMLModel:
    """
    Unsupervised Anomaly Detection using scikit-learn's IsolationForest.
    Trains on 12-feature vectors of historical signups to isolate atypical patterns.
    Provides a graceful statistical distance fallback if scikit-learn is unavailable.
    """
    def __init__(self):
        self.model = None
        self.baseline_mean = None
        self.baseline_std = None

    def train(self, historical_data):
        if not historical_data or not isinstance(historical_data, (list, tuple)):
            self.model = None
            return

        # Sanitize rows to ensure 12 valid numerical elements per row
        sanitized = []
        for row in historical_data:
            if isinstance(row, (list, tuple)) and len(row) == 12:
                try:
                    sanitized.append([_safe_float(x) for x in row])
                except Exception:
                    continue

        if len(sanitized) < 5:
            self.model = None
            return

        if SKLEARN_AVAILABLE and len(sanitized) >= 10:
            try:
                self.model = IsolationForest(
                    n_estimators=100,
                    contamination=0.15,
                    random_state=42
                )
                self.model.fit(sanitized)
                return
            except Exception as e:
                print(f"[FraudGuard ML] IsolationForest training fallback ({e})")

        # Heuristic statistical baseline calculation
        try:
            num_features = 12
            self.baseline_mean = [
                sum(row[i] for row in sanitized) / len(sanitized)
                for i in range(num_features)
            ]
            self.baseline_std = [
                math.sqrt(sum((row[i] - self.baseline_mean[i])**2 for row in sanitized) / len(sanitized)) + 1e-4
                for i in range(num_features)
            ]
        except Exception:
            pass

    def predict(self, features):
        if not isinstance(features, (list, tuple)):
            features = [0.0] * 12
        else:
            features = [_safe_float(x) for x in features]
            if len(features) < 12:
                features = features + [0.0] * (12 - len(features))
            elif len(features) > 12:
                features = features[:12]

        # 1. Isolation Forest prediction if fitted
        if self.model is not None and SKLEARN_AVAILABLE:
            try:
                prediction = self.model.predict([features])[0]
                raw_score = self.model.decision_function([features])[0]
                anomaly_score = int(max(0, min(100, 50 - raw_score * 100)))
                if prediction == -1:
                    anomaly_score = max(anomaly_score, 70)
                return anomaly_score
            except Exception:
                pass

        # 2. Statistical Z-distance heuristic fallback
        if self.baseline_mean and self.baseline_std:
            try:
                z_scores = [
                    abs(features[i] - self.baseline_mean[i]) / self.baseline_std[i]
                    for i in range(min(len(features), len(self.baseline_mean)))
                ]
                avg_z = sum(z_scores) / len(z_scores)
                # Map avg Z-score to 0-100 anomaly range
                return int(max(0, min(100, round(avg_z * 22))))
            except Exception:
                pass

        # 3. Default feature magnitude heuristic
        high_risk_weight = (
            features[0] * 0.25   # device score
            + features[1] * 0.20 # email score
            + features[2] * 0.20 # ip score
            + features[4] * 0.15 # velocity score
            + features[5] * 0.20 # behavior score
        )
        return int(max(0, min(100, round(high_risk_weight * 0.7))))
