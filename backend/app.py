import os
import json
from datetime import datetime, timezone, timedelta

from flask import Flask, jsonify, request
from flask_cors import CORS

from database import get_connection, init_database
from risk_engine import (
    analyze_device,
    analyze_email,
    analyze_ip,
    analyze_user_agent,
    analyze_velocity,
    calculate_behavior_score,
    calculate_final_score,
    build_feature_vector,
    create_device_fingerprint,
    determine_action,
    normalize_email,
    FraudMLModel,
    _safe_float,
    _safe_int,
    _safe_str,
)


# ============================================================
# APP CONFIGURATION
# ============================================================

app = Flask(__name__)

# Request payload limit: protect against memory exhaustion / payload flooding (1 MB)
app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024

# CORS Origin Configuration
# In development, restrict to safe local origins (Vite on 5173, Flask on 5000, 3000)
# In production, set ALLOWED_ORIGINS to trusted comma-separated origin URLs
allowed_origins_env = os.environ.get("ALLOWED_ORIGINS", "").strip()
if allowed_origins_env:
    allowed_origins = [o.strip() for o in allowed_origins_env.split(",") if o.strip()]
else:
    allowed_origins = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:5000",
        "http://127.0.0.1:5000",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]
CORS(app, resources={r"/api/*": {"origins": allowed_origins if allowed_origins != ["*"] else "*"}})


# ============================================================
# ADMINISTRATIVE AUTHORIZATION
# ============================================================

def check_admin_authorization():
    """
    Verifies administrative authorization for sensitive/state-changing endpoints.
    If ADMIN_API_KEY is configured in the environment, requests must provide matching
    'X-Admin-Key' or 'Authorization: Bearer <key>' headers.
    If ADMIN_API_KEY is unset (default for local demonstration mode), access is permitted
    with an explicit warning log.
    """
    admin_key = os.environ.get("ADMIN_API_KEY", "").strip()
    if not admin_key:
        return True, None

    auth_header = request.headers.get("Authorization", "").strip()
    admin_header = request.headers.get("X-Admin-Key", "").strip()

    token = admin_header
    if not token and auth_header.startswith("Bearer "):
        token = auth_header[7:].strip()

    if token == admin_key:
        return True, None

    return False, (jsonify({"error": "Unauthorized: Invalid or missing admin API key"}), 401)


@app.errorhandler(413)
def request_entity_too_large(e):
    return jsonify({"error": "Payload exceeds maximum allowed size (1 MB)"}), 413


# Safe database initialization
try:
    init_database()
except Exception as e:
    print(f"[FraudGuard] Database initialization notice: {e}")


# ============================================================
# MACHINE LEARNING MODEL
# ============================================================

ml_model = FraudMLModel()


# ============================================================
# UTILITY FUNCTIONS
# ============================================================

def now_iso():
    return datetime.now(timezone.utc).isoformat()


def get_client_ip():
    """
    Get client IP address from proxy headers or remote socket.
    """
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "127.0.0.1"


def risk_level(score):
    if score >= 85:
        return "CRITICAL"
    if score >= 70:
        return "HIGH"
    if score >= 50:
        return "MEDIUM"
    return "LOW"


# ============================================================
# DATABASE HELPERS
# ============================================================

def count_device(device_fingerprint, cursor=None):
    if cursor is not None:
        cursor.execute(
            "SELECT COUNT(*) AS count FROM users WHERE device_fingerprint = %s",
            (device_fingerprint,)
        )
        row = cursor.fetchone()
        return row["count"] if row else 0

    connection = get_connection()
    try:
        cur = connection.cursor()
        cur.execute(
            "SELECT COUNT(*) AS count FROM users WHERE device_fingerprint = %s",
            (device_fingerprint,)
        )
        row = cur.fetchone()
        return row["count"] if row else 0
    finally:
        connection.close()


def count_ip(ip_address, cursor=None):
    if cursor is not None:
        cursor.execute(
            "SELECT COUNT(*) AS count FROM users WHERE ip_address = %s",
            (ip_address,)
        )
        row = cursor.fetchone()
        return row["count"] if row else 0

    connection = get_connection()
    try:
        cur = connection.cursor()
        cur.execute(
            "SELECT COUNT(*) AS count FROM users WHERE ip_address = %s",
            (ip_address,)
        )
        row = cur.fetchone()
        return row["count"] if row else 0
    finally:
        connection.close()


def count_recent_signups(ip_address, cursor=None):
    cutoff = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
    if cursor is not None:
        cursor.execute(
            "SELECT COUNT(*) AS count FROM signup_events WHERE ip_address = %s AND timestamp >= %s",
            (ip_address, cutoff)
        )
        row = cursor.fetchone()
        return row["count"] if row else 0

    connection = get_connection()
    try:
        cur = connection.cursor()
        cur.execute(
            "SELECT COUNT(*) AS count FROM signup_events WHERE ip_address = %s AND timestamp >= %s",
            (ip_address, cutoff)
        )
        row = cur.fetchone()
        return row["count"] if row else 0
    finally:
        connection.close()


def count_normalized_email(norm_email, cursor=None):
    """
    Check if any existing registered account shares the same canonical email
    (ignoring plus-aliases and dots in gmail).
    """
    if cursor is not None:
        cursor.execute("SELECT email FROM users")
        rows = cursor.fetchall()
        return sum(1 for r in rows if normalize_email(r.get("email", "")) == norm_email)

    connection = get_connection()
    try:
        cur = connection.cursor()
        cur.execute("SELECT email FROM users")
        rows = cur.fetchall()
        return sum(1 for r in rows if normalize_email(r.get("email", "")) == norm_email)
    finally:
        connection.close()


# ============================================================
# FRAUD CLUSTERING
# ============================================================

def upsert_cluster(cursor, cluster_key, cluster_type, member_ids, reason, timestamp):
    if len(member_ids) < 2:
        return

    cluster_score = min(100, 20 + (len(member_ids) - 1) * 15)

    cursor.execute(
        """
        INSERT INTO fraud_clusters (
            cluster_key, cluster_type, cluster_score,
            reason, created_at, updated_at
        )
        VALUES (%s, %s, %s, %s, %s, %s)
        ON CONFLICT (cluster_key)
        DO UPDATE SET
            cluster_score = EXCLUDED.cluster_score,
            reason = EXCLUDED.reason,
            updated_at = EXCLUDED.updated_at
        RETURNING id
        """,
        (
            cluster_key,
            cluster_type,
            cluster_score,
            reason,
            timestamp,
            timestamp,
        )
    )

    row = cursor.fetchone()
    cluster_id = row["id"] if row else cursor.lastrowid

    for member_id in member_ids:
        cursor.execute(
            """
            INSERT INTO cluster_members (
                cluster_id, user_id, relationship_type
            )
            VALUES (%s, %s, %s)
            ON CONFLICT (cluster_id, user_id) DO NOTHING
            """,
            (cluster_id, member_id, cluster_type)
        )


def sync_fraud_clusters(cursor, device_fingerprint, ip_address, timestamp):
    if device_fingerprint:
        cursor.execute(
            "SELECT id FROM users WHERE device_fingerprint = %s",
            (device_fingerprint,)
        )
        device_members = [row["id"] for row in cursor.fetchall()]
        if len(device_members) >= 2:
            upsert_cluster(
                cursor,
                cluster_key=f"device:{device_fingerprint}",
                cluster_type="SHARED_DEVICE",
                member_ids=device_members,
                reason=f"{len(device_members)} accounts share the same device hardware fingerprint",
                timestamp=timestamp,
            )

    if ip_address:
        cursor.execute(
            "SELECT id FROM users WHERE ip_address = %s",
            (ip_address,)
        )
        ip_members = [row["id"] for row in cursor.fetchall()]
        if len(ip_members) >= 2:
            upsert_cluster(
                cursor,
                cluster_key=f"ip:{ip_address}",
                cluster_type="SHARED_IP",
                member_ids=ip_members,
                reason=f"{len(ip_members)} accounts share the same IP address ({ip_address})",
                timestamp=timestamp,
            )


# ============================================================
# SEED INITIAL DATA (WARM-UP BASELINE)
# ============================================================

def seed_initial_data_if_empty():
    """
    Seeds initial realistic accounts if the database is newly initialized,
    providing immediate threat intelligence, cluster tracking, and ML warmup.
    """
    conn = None
    try:
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) AS count FROM users")
        count = cur.fetchone()["count"]
        if count > 0:
            return

        print("[FraudGuard] Seeding initial baseline accounts for immediate evaluation...")
        base_time = datetime.now(timezone.utc) - timedelta(hours=2)

        demo_accounts = [
            {
                "name": "Sarah Jenkins",
                "email": "sarah.j@example.com",
                "ip": "198.51.100.24",
                "device": "fp_legit_001_8a7d",
                "sw": 1920, "sh": 1080, "tz": "America/New_York",
                "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
                "form_fill_time": 14.2, "mouse": 48, "clicks": 5, "pastes": 0, "focus": 1,
            },
            {
                "name": "Marcus Vance",
                "email": "marcus.vance@techcorp.io",
                "ip": "203.0.113.88",
                "device": "fp_legit_002_4b9c",
                "sw": 1440, "sh": 900, "tz": "Europe/London",
                "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/122.0.0.0",
                "form_fill_time": 11.8, "mouse": 36, "clicks": 4, "pastes": 0, "focus": 0,
            },
            {
                "name": "CryptoHunter99",
                "email": "airdrop999@tempmail.com",
                "ip": "192.0.2.140",
                "device": "fp_botnet_001_d3f1",
                "sw": 1366, "sh": 768, "tz": "Asia/Kolkata",
                "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                "form_fill_time": 1.4, "mouse": 1, "clicks": 1, "pastes": 3, "focus": 4,
            },
            {
                "name": "Alex Mercer",
                "email": "alex.mercer+trial1@gmail.com",
                "ip": "192.0.2.140",
                "device": "fp_botnet_001_d3f1",
                "sw": 1366, "sh": 768, "tz": "Asia/Kolkata",
                "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                "form_fill_time": 2.1, "mouse": 2, "clicks": 1, "pastes": 2, "focus": 2,
            },
            {
                "name": "Alex Mercer 2",
                "email": "alex.mercer+trial2@gmail.com",
                "ip": "192.0.2.140",
                "device": "fp_botnet_001_d3f1",
                "sw": 1366, "sh": 768, "tz": "Asia/Kolkata",
                "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) HeadlessChrome/120.0",
                "form_fill_time": 0.8, "mouse": 0, "clicks": 1, "pastes": 4, "focus": 0,
            },
            {
                "name": "Elena Rostova",
                "email": "elena.rostova@globaltravel.org",
                "ip": "198.51.100.115",
                "device": "fp_legit_003_9e2a",
                "sw": 2560, "sh": 1440, "tz": "Europe/Berlin",
                "ua": "Mozilla/5.0 (X11; Linux x86_64) Firefox/123.0",
                "form_fill_time": 9.5, "mouse": 29, "clicks": 3, "pastes": 0, "focus": 1,
            },
        ]

        for i, acc in enumerate(demo_accounts):
            ts = (base_time + timedelta(minutes=i * 18)).isoformat()
            
            # Simulate device/IP counts
            cur.execute("SELECT COUNT(*) AS c FROM users WHERE device_fingerprint = %s", (acc["device"],))
            dev_c = cur.fetchone()["c"]
            cur.execute("SELECT COUNT(*) AS c FROM users WHERE ip_address = %s", (acc["ip"],))
            ip_c = cur.fetchone()["c"]

            dev_score, dev_sigs = analyze_device(acc["device"], dev_c)
            em_score, em_sigs = analyze_email(acc["email"])
            ip_score, ip_sigs = analyze_ip(acc["ip"], ip_c)
            ua_score, ua_sigs = analyze_user_agent(acc["ua"])
            beh_score, beh_sigs = calculate_behavior_score(acc)

            all_sigs = dev_sigs + em_sigs + ip_sigs + ua_sigs + beh_sigs
            rule_score = min(100, dev_score + em_score + ip_score + ua_score)
            
            final_s = calculate_final_score(
                rule_score=rule_score,
                behavior_score=beh_score,
                ml_score=0,
                device_accounts=dev_c,
                ip_accounts=ip_c,
                recent_signups=0,
                signal_count=len(all_sigs)
            )

            act, sev = determine_action(final_s)
            lvl = risk_level(final_s)

            cur.execute("""
                INSERT INTO users (
                    name, email, ip_address, device_fingerprint,
                    screen_width, screen_height, timezone, user_agent,
                    signup_time, created_at, risk_score, risk_level, action
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id
            """, (
                acc["name"], acc["email"], acc["ip"], acc["device"],
                acc["sw"], acc["sh"], acc["tz"], acc["ua"],
                ts, ts, final_s, lvl, act
            ))
            
            row = cur.fetchone()
            uid = row["id"] if row else cur.lastrowid

            for sig in all_sigs:
                cur.execute("""
                    INSERT INTO risk_signals (user_id, signal_type, severity, points, message, created_at)
                    VALUES (%s, %s, %s, %s, %s, %s)
                """, (uid, sig["type"], sig["severity"], sig["points"], sig["message"], ts))

            features = build_feature_vector(
                device_score=dev_score, email_score=em_score, ip_score=ip_score,
                user_agent_score=ua_score, velocity_score=0, behavior_score=beh_score,
                form_fill_time=acc["form_fill_time"], mouse_movements=acc["mouse"],
                paste_count=acc["pastes"], focus_changes=acc["focus"]
            )

            cur.execute("""
                INSERT INTO risk_assessments (
                    user_id, rule_score, ml_score, behavior_score,
                    final_score, decision, ml_features, created_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """, (uid, rule_score, 0, beh_score, final_s, act, json.dumps(features), ts))

            sync_fraud_clusters(cur, acc["device"], acc["ip"], ts)

        conn.commit()
        print("[FraudGuard] Baseline accounts seeded successfully.")
    except Exception as e:
        if conn:
            conn.rollback()
        print(f"[FraudGuard] Seeding notice: {e}")
    finally:
        if conn:
            conn.close()


# Run seed check
seed_initial_data_if_empty()


# ============================================================
# HEALTH CHECK
# ============================================================

@app.route("/api/health", methods=["GET"])
def health():
    connection = None
    database_status = "error"
    try:
        connection = get_connection()
        cursor = connection.cursor()
        cursor.execute("SELECT 1")
        database_status = "connected"
    except Exception as err:
        print(f"[FraudGuard] Database health check error: {err}")
        database_status = "error: connection failed"
    finally:
        if connection:
            connection.close()

    return jsonify({
        "status": "ok",
        "service": "FraudGuard Risk Engine",
        "database": database_status,
        "timestamp": now_iso()
    })


# ============================================================
# SIGNUP / FRAUD ANALYSIS
# ============================================================

@app.route("/api/signup", methods=["POST"])
def signup():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "No signup data received or invalid JSON payload"}), 400

    name = str(data.get("name", "")).strip()
    email = str(data.get("email", "")).strip().lower()

    if not name or not email:
        return jsonify({"error": "Name and email are required"}), 400

    if len(name) > 255:
        return jsonify({"error": "Name exceeds maximum allowed length (255 characters)"}), 400

    if len(email) > 254:
        return jsonify({"error": "Email exceeds maximum allowed length (254 characters)"}), 400

    ip_address = get_client_ip()
    device_fingerprint = create_device_fingerprint(data)

    connection = get_connection()
    try:
        cursor = connection.cursor()

        existing_device_count = count_device(device_fingerprint, cursor)
        existing_ip_count = count_ip(ip_address, cursor)
        recent_signup_count = count_recent_signups(ip_address, cursor)

        # 1. Rule Engine
        device_score, device_signals = analyze_device(device_fingerprint, existing_device_count)
        email_score, email_signals = analyze_email(email)
        ip_score, ip_signals = analyze_ip(ip_address, existing_ip_count)
        user_agent_score, user_agent_signals = analyze_user_agent(data.get("user_agent"))
        velocity_score, velocity_signals = analyze_velocity(recent_signup_count)

        # Check for alias reuse (+ subaddress abuse)
        norm_email = normalize_email(email)
        existing_norm_count = count_normalized_email(norm_email, cursor)
        if existing_norm_count > 0 and "+" in email.split("@")[0]:
            email_score += 20
            email_signals.append({
                "type": "EMAIL_ALIAS_REUSE",
                "severity": "HIGH",
                "points": 20,
                "message": f"Canonical mailbox '{norm_email}' has already been used by an existing account"
            })

        # 2. Behavior Engine
        behavior_score, behavior_signals = calculate_behavior_score(data)

        # Collect signals
        signals = []
        signals.extend(device_signals)
        signals.extend(email_signals)
        signals.extend(ip_signals)
        signals.extend(user_agent_signals)
        signals.extend(velocity_signals)
        signals.extend(behavior_signals)

        rule_score = min(
            100,
            device_score + email_score + ip_score + user_agent_score + velocity_score
        )

        ml_features = build_feature_vector(
            device_score=device_score,
            email_score=email_score,
            ip_score=ip_score,
            user_agent_score=user_agent_score,
            velocity_score=velocity_score,
            behavior_score=behavior_score,
            form_fill_time=data.get("form_fill_time", 0),
            mouse_movements=data.get("mouse_movements", 0),
            paste_count=data.get("paste_count", 0),
            focus_changes=data.get("focus_changes", 0),
            hardware_concurrency=data.get("hardware_concurrency", 0),
            max_touch_points=data.get("max_touch_points", 0),
        )

        # 3. ML Model Train & Predict
        ml_score = 0
        try:
            cursor.execute(
                """
                SELECT ml_features FROM risk_assessments
                WHERE ml_features IS NOT NULL
                ORDER BY id DESC LIMIT 200
                """
            )
            historical_rows = cursor.fetchall()
            historical_features = []
            for row in historical_rows:
                try:
                    historical_features.append(json.loads(row["ml_features"]))
                except (TypeError, ValueError):
                    continue

            if historical_features:
                ml_model.train(historical_features)
                ml_score = ml_model.predict(ml_features)
        except Exception as error:
            print("[FraudGuard ML] Inference notice:", error)
            ml_score = 0

        # 4. Final Risk Fusion
        final_score = calculate_final_score(
            rule_score=rule_score,
            behavior_score=behavior_score,
            ml_score=ml_score,
            device_accounts=existing_device_count,
            ip_accounts=existing_ip_count,
            recent_signups=recent_signup_count,
            signal_count=len(signals),
        )

        action, severity = determine_action(final_score)
        level = risk_level(final_score)

        # 5. Persist to Database within single transaction
        created_at = now_iso()

        cursor.execute(
            """
            INSERT INTO users (
                name, email, ip_address, device_fingerprint,
                screen_width, screen_height, timezone, user_agent,
                signup_time, created_at, risk_score, risk_level, action
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id
            """,
            (
                name, email, ip_address, device_fingerprint,
                _safe_int(data.get("screen_width")) if data.get("screen_width") is not None else None,
                _safe_int(data.get("screen_height")) if data.get("screen_height") is not None else None,
                _safe_str(data.get("timezone", ""))[:64],
                _safe_str(data.get("user_agent", ""))[:512],
                _safe_str(data.get("signup_time", ""))[:64],
                created_at,
                final_score, level, action,
            )
        )

        row = cursor.fetchone()
        user_id = row["id"] if row else cursor.lastrowid

        for signal in signals:
            cursor.execute(
                """
                INSERT INTO risk_signals (
                    user_id, signal_type, severity, points, message, created_at
                )
                VALUES (%s, %s, %s, %s, %s, %s)
                """,
                (
                    user_id, signal["type"], signal["severity"],
                    signal["points"], signal["message"], created_at,
                )
            )

        cursor.execute(
            """
            INSERT INTO signup_events (
                user_id, ip_address, device_fingerprint, timestamp
            )
            VALUES (%s, %s, %s, %s)
            """,
            (user_id, ip_address, device_fingerprint, created_at)
        )

        cursor.execute(
            """
            INSERT INTO risk_assessments (
                user_id, rule_score, ml_score, behavior_score,
                final_score, decision, ml_features, created_at
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                user_id, rule_score, ml_score, behavior_score,
                final_score, action, json.dumps(ml_features), created_at,
            )
        )

        sync_fraud_clusters(cursor, device_fingerprint, ip_address, created_at)

        connection.commit()

        return jsonify({
            "message": "Account analyzed successfully",
            "user_id": user_id,
            "risk_score": final_score,
            "risk_level": level,
            "action": action,
            "severity": severity,
            "signals": signals,
            "scores": {
                "rule_score": rule_score,
                "behavior_score": behavior_score,
                "ml_score": ml_score,
            },
            "intelligence": {
                "device_accounts": existing_device_count,
                "ip_accounts": existing_ip_count,
                "recent_signups": recent_signup_count,
                "device_fingerprint": device_fingerprint[:16] + "...",
            }
        }), 201
    except Exception as err:
        connection.rollback()
        print(f"[FraudGuard] Signup error: {err}")
        return jsonify({"error": "Failed to process signup evaluation"}), 500
    finally:
        connection.close()


# ============================================================
# USERS
# ============================================================

@app.route("/api/users", methods=["GET"])
def get_users():
    connection = get_connection()
    try:
        cursor = connection.cursor()
        cursor.execute(
            """
            SELECT
                id, name, email, ip_address, risk_score,
                risk_level, action, created_at
            FROM users
            ORDER BY id DESC
            """
        )
        rows = cursor.fetchall()
        return jsonify([dict(row) for row in rows])
    except Exception as err:
        print(f"[FraudGuard] Get users error: {err}")
        return jsonify({"error": "Failed to fetch users"}), 500
    finally:
        connection.close()


# ============================================================
# USER DETAILS (WITH SIGNALS & ASSESSMENTS)
# ============================================================

@app.route("/api/users/<int:user_id>", methods=["GET"])
def get_user(user_id):
    connection = get_connection()
    try:
        cursor = connection.cursor()

        cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        user = cursor.fetchone()

        if not user:
            return jsonify({"error": "User not found"}), 404

        cursor.execute(
            """
            SELECT signal_type, severity, points, message, created_at
            FROM risk_signals
            WHERE user_id = %s
            ORDER BY id DESC
            """,
            (user_id,)
        )
        signals = cursor.fetchall()

        cursor.execute(
            """
            SELECT id, rule_score, ml_score, behavior_score, final_score, decision, created_at
            FROM risk_assessments
            WHERE user_id = %s
            ORDER BY id DESC
            """,
            (user_id,)
        )
        assessments = cursor.fetchall()

        return jsonify({
            "user": dict(user),
            "signals": [dict(row) for row in signals],
            "assessments": [dict(row) for row in assessments],
        })
    except Exception as err:
        print(f"[FraudGuard] Get user details error: {err}")
        return jsonify({"error": "Failed to fetch user details"}), 500
    finally:
        connection.close()


# ============================================================
# FRAUD CLUSTERS
# ============================================================

@app.route("/api/clusters", methods=["GET"])
def get_clusters():
    connection = get_connection()
    try:
        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT
                fc.id, fc.cluster_type, fc.cluster_score, fc.reason,
                fc.status, fc.updated_at,
                COUNT(cm.user_id) AS member_count
            FROM fraud_clusters fc
            JOIN cluster_members cm ON cm.cluster_id = fc.id
            GROUP BY fc.id, fc.cluster_type, fc.cluster_score,
                     fc.reason, fc.status, fc.updated_at
            ORDER BY fc.cluster_score DESC
            """
        )
        clusters = cursor.fetchall()

        cluster_list = []
        for cluster in clusters:
            cursor.execute(
                """
                SELECT u.id, u.name, u.email, u.risk_score, u.action
                FROM cluster_members cm
                JOIN users u ON u.id = cm.user_id
                WHERE cm.cluster_id = %s
                ORDER BY u.id DESC
                """,
                (cluster["id"],)
            )
            members = cursor.fetchall()
            cluster_dict = dict(cluster)
            cluster_dict["members"] = [dict(m) for m in members]
            cluster_list.append(cluster_dict)

        return jsonify(cluster_list)
    except Exception as err:
        print(f"[FraudGuard] Get clusters error: {err}")
        return jsonify({"error": "Failed to fetch fraud clusters"}), 500
    finally:
        connection.close()


@app.route("/api/reset-demo", methods=["POST"])
def reset_demo():
    authorized, error_response = check_admin_authorization()
    if not authorized:
        return error_response

    tables = [
        "cluster_members", "fraud_clusters", "risk_assessments",
        "signup_events", "risk_signals", "users"
    ]
    conn = None
    try:
        conn = get_connection()
        cur = conn.cursor()
        for table in tables:
            cur.execute(f"DELETE FROM {table}")
        conn.commit()
    except Exception as e:
        if conn:
            conn.rollback()
        print(f"[FraudGuard] Reset demo error: {e}")
        return jsonify({"error": "Reset procedure failed"}), 500
    finally:
        if conn:
            conn.close()

    # Reseed initial baseline dataset
    seed_initial_data_if_empty()
    return jsonify({"status": "reset complete", "message": "Demo data reset and refreshed"}), 200


# ============================================================
# INTERACTIVE VERIFICATION (GRADUATED CHALLENGE TIER)
# ============================================================

@app.route("/api/verify/<int:user_id>", methods=["POST"])
def verify_user(user_id):
    connection = get_connection()
    try:
        cursor = connection.cursor()

        cursor.execute("SELECT id, action FROM users WHERE id = %s", (user_id,))
        user = cursor.fetchone()

        if not user:
            return jsonify({"error": "User not found"}), 404

        verified_at = now_iso()
        new_action = user["action"]
        if user["action"] == "CHALLENGE":
            new_action = "ALLOW"

        cursor.execute(
            """
            UPDATE users
            SET verified = TRUE, verified_at = %s, action = %s
            WHERE id = %s
            """,
            (verified_at, new_action, user_id)
        )

        connection.commit()

        return jsonify({
            "status": "verified",
            "user_id": user_id,
            "action": new_action,
        }), 200
    except Exception as err:
        connection.rollback()
        print(f"[FraudGuard] Verification error: {err}")
        return jsonify({"error": "Verification failed"}), 500
    finally:
        connection.close()


# ============================================================
# CLUSTER ADMIN ACTIONS
# ============================================================

@app.route("/api/clusters/<int:cluster_id>/action", methods=["POST"])
def cluster_action(cluster_id):
    authorized, error_response = check_admin_authorization()
    if not authorized:
        return error_response

    data = request.get_json(silent=True) or {}
    new_status = data.get("status")

    if new_status not in ("ACTIVE", "FLAGGED", "RESTRICTED"):
        return jsonify({"error": "Invalid status"}), 400

    connection = get_connection()
    try:
        cursor = connection.cursor()

        cursor.execute(
            """
            UPDATE fraud_clusters
            SET status = %s, updated_at = %s
            WHERE id = %s
            RETURNING id
            """,
            (new_status, now_iso(), cluster_id)
        )

        updated = cursor.fetchone()
        connection.commit()

        if not updated:
            return jsonify({"error": "Cluster not found"}), 404

        return jsonify({
            "status": "updated",
            "cluster_id": cluster_id,
            "new_status": new_status,
        }), 200
    except Exception as err:
        connection.rollback()
        print(f"[FraudGuard] Cluster action error: {err}")
        return jsonify({"error": "Failed to update cluster status"}), 500
    finally:
        connection.close()


# ============================================================
# DASHBOARD STATISTICS
# ============================================================

@app.route("/api/dashboard", methods=["GET"])
def dashboard():
    connection = get_connection()
    try:
        cursor = connection.cursor()

        cursor.execute("SELECT COUNT(*) AS count FROM users")
        total_users = cursor.fetchone()["count"]

        cursor.execute("SELECT COUNT(*) AS count FROM users WHERE risk_score >= 70")
        high_risk = cursor.fetchone()["count"]

        cursor.execute("SELECT COUNT(*) AS count FROM users WHERE action = 'BLOCK'")
        blocked = cursor.fetchone()["count"]

        cursor.execute("SELECT COUNT(*) AS count FROM users WHERE action = 'REVIEW'")
        review = cursor.fetchone()["count"]

        cursor.execute("SELECT COUNT(*) AS count FROM users WHERE action = 'CHALLENGE'")
        challenge = cursor.fetchone()["count"]

        cursor.execute("SELECT AVG(risk_score) AS avg_risk FROM users")
        avg_row = cursor.fetchone()
        average_risk = avg_row["avg_risk"] if avg_row else 0

        cursor.execute("SELECT risk_level, COUNT(*) AS count FROM users GROUP BY risk_level")
        dist_rows = cursor.fetchall()
        counts_by_level = {r["risk_level"]: r["count"] for r in dist_rows}

        # Ensure all 4 risk levels are represented in the profile
        full_distribution = [
            {"risk_level": "LOW", "count": counts_by_level.get("LOW", 0)},
            {"risk_level": "MEDIUM", "count": counts_by_level.get("MEDIUM", 0)},
            {"risk_level": "HIGH", "count": counts_by_level.get("HIGH", 0)},
            {"risk_level": "CRITICAL", "count": counts_by_level.get("CRITICAL", 0)},
        ]

        cursor.execute("SELECT COUNT(*) AS count FROM fraud_clusters")
        active_clusters = cursor.fetchone()["count"]

        return jsonify({
            "total_users": total_users,
            "high_risk": high_risk,
            "blocked": blocked,
            "review": review,
            "challenge": challenge,
            "active_clusters": active_clusters,
            "average_risk": round(float(average_risk) if average_risk is not None else 0, 1),
            "risk_distribution": full_distribution,
        })
    except Exception as err:
        print(f"[FraudGuard] Dashboard stats error: {err}")
        return jsonify({"error": "Failed to retrieve dashboard metrics"}), 500
    finally:
        connection.close()


# ============================================================
# RUN SERVER
# ============================================================

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug_mode = os.environ.get("FLASK_DEBUG", "0").lower() in ("1", "true", "yes")
    # Never bind to 0.0.0.0 when debug is enabled
    host = "127.0.0.1" if debug_mode else os.environ.get("HOST", "127.0.0.1")
    app.run(
        debug=debug_mode,
        host=host,
        port=port,
    )
