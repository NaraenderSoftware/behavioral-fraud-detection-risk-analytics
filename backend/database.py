import os
import re
import sqlite3

# Try importing psycopg2 for PostgreSQL support
try:
    import psycopg2
    import psycopg2.extras
    PSYCOPG2_AVAILABLE = True
except ImportError:
    PSYCOPG2_AVAILABLE = False


# ============================================================
# DATABASE CONFIGURATION & RESOLUTION
# ============================================================

DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()

# Determine backend engine: 'postgres' or 'sqlite'
def get_engine_type():
    if DATABASE_URL.startswith("postgres://") or DATABASE_URL.startswith("postgresql://"):
        if PSYCOPG2_AVAILABLE:
            return "postgres"
    return "sqlite"

SQLITE_DB_PATH = os.path.join(os.path.dirname(__file__), "fraudguard.db")


# ============================================================
# SQLITE COMPATIBILITY WRAPPERS
# ============================================================

class SQLiteCursorWrapper:
    """
    Wraps sqlite3.Cursor to provide a consistent interface with psycopg2.
    Translates '%s' parameter markers to '?' automatically.
    Supports dictionary-like row access (RealDictRow parity).
    """
    def __init__(self, cursor):
        self._cursor = cursor

    def execute(self, query, params=None):
        # Translate %s to ? for SQLite parameter binding
        translated_query = query.replace("%s", "?")
        
        # Handle PostgreSQL TRUNCATE ... RESTART IDENTITY CASCADE on SQLite
        if "TRUNCATE TABLE" in translated_query.upper():
            match = re.search(r"TRUNCATE\s+TABLE\s+(\w+)", translated_query, re.IGNORECASE)
            if match:
                table_name = match.group(1)
                translated_query = f"DELETE FROM {table_name}"

        if params is None:
            return self._cursor.execute(translated_query)
        return self._cursor.execute(translated_query, params)

    def executemany(self, query, seq_of_params):
        translated_query = query.replace("%s", "?")
        return self._cursor.executemany(translated_query, seq_of_params)

    def fetchone(self):
        row = self._cursor.fetchone()
        if row is None:
            return None
        return dict(row)

    def fetchall(self):
        rows = self._cursor.fetchall()
        return [dict(r) for r in rows]

    def close(self):
        self._cursor.close()

    @property
    def rowcount(self):
        return self._cursor.rowcount

    @property
    def lastrowid(self):
        return self._cursor.lastrowid


class SQLiteConnectionWrapper:
    """
    Wraps sqlite3.Connection so cursor() returns the SQLiteCursorWrapper.
    """
    def __init__(self, conn):
        self._conn = conn
        self._conn.row_factory = sqlite3.Row
        try:
            self._conn.execute("PRAGMA foreign_keys = ON")
        except Exception:
            pass

    def cursor(self):
        return SQLiteCursorWrapper(self._conn.cursor())

    def commit(self):
        self._conn.commit()

    def rollback(self):
        self._conn.rollback()

    def close(self):
        self._conn.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type:
            self.rollback()
        else:
            self.commit()
        self.close()


# ============================================================
# CONNECTION FACTORY
# ============================================================

def get_connection():
    """
    Returns a database connection with dict-like row access.
    Uses PostgreSQL if DATABASE_URL is configured and psycopg2 is available;
    otherwise seamlessly uses SQLite (backend/fraudguard.db).
    """
    engine = get_engine_type()

    if engine == "postgres":
        try:
            return psycopg2.connect(
                DATABASE_URL,
                cursor_factory=psycopg2.extras.RealDictCursor,
            )
        except Exception as e:
            # Fall back to SQLite if PostgreSQL fails to connect
            print(f"[FraudGuard] PostgreSQL connection failed ({e}). Falling back to local SQLite.")
            conn = sqlite3.connect(SQLITE_DB_PATH)
            return SQLiteConnectionWrapper(conn)
    else:
        conn = sqlite3.connect(SQLITE_DB_PATH)
        return SQLiteConnectionWrapper(conn)


# ============================================================
# INITIALIZE DATABASE SCHEMA
# ============================================================

def init_database():
    """
    Create all FraudGuard tables, indexes, and initial constraints if they don't exist.
    Compatible with both SQLite and PostgreSQL.
    """
    connection = get_connection()
    cursor = connection.cursor()

    engine = "sqlite" if isinstance(connection, SQLiteConnectionWrapper) else "postgres"

    # Auto-increment keyword varies by engine
    pk_def = "INTEGER PRIMARY KEY AUTOINCREMENT" if engine == "sqlite" else "SERIAL PRIMARY KEY"
    bool_default = "0" if engine == "sqlite" else "FALSE"

    # 1. USERS
    cursor.execute(f"""
        CREATE TABLE IF NOT EXISTS users (
            id {pk_def},
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            ip_address TEXT,
            device_fingerprint TEXT,
            screen_width INTEGER,
            screen_height INTEGER,
            timezone TEXT,
            user_agent TEXT,
            signup_time TEXT,
            created_at TEXT NOT NULL,
            risk_score INTEGER DEFAULT 0,
            risk_level TEXT DEFAULT 'LOW',
            action TEXT DEFAULT 'ALLOW',
            verified BOOLEAN DEFAULT {bool_default},
            verified_at TEXT
        )
    """)

    # 2. RISK SIGNALS
    cursor.execute(f"""
        CREATE TABLE IF NOT EXISTS risk_signals (
            id {pk_def},
            user_id INTEGER NOT NULL REFERENCES users(id),
            signal_type TEXT NOT NULL,
            severity TEXT,
            points INTEGER DEFAULT 0,
            message TEXT,
            created_at TEXT NOT NULL
        )
    """)

    # 3. SIGNUP EVENTS
    cursor.execute(f"""
        CREATE TABLE IF NOT EXISTS signup_events (
            id {pk_def},
            user_id INTEGER REFERENCES users(id),
            ip_address TEXT,
            device_fingerprint TEXT,
            timestamp TEXT NOT NULL
        )
    """)

    # 4. RISK ASSESSMENTS
    cursor.execute(f"""
        CREATE TABLE IF NOT EXISTS risk_assessments (
            id {pk_def},
            user_id INTEGER NOT NULL REFERENCES users(id),
            rule_score INTEGER DEFAULT 0,
            ml_score INTEGER DEFAULT 0,
            behavior_score INTEGER DEFAULT 0,
            final_score INTEGER DEFAULT 0,
            decision TEXT,
            ml_features TEXT,
            created_at TEXT NOT NULL
        )
    """)

    # 5. FRAUD CLUSTERS
    cursor.execute(f"""
        CREATE TABLE IF NOT EXISTS fraud_clusters (
            id {pk_def},
            cluster_key TEXT UNIQUE,
            cluster_type TEXT,
            cluster_score INTEGER DEFAULT 0,
            reason TEXT,
            status TEXT DEFAULT 'ACTIVE',
            created_at TEXT NOT NULL,
            updated_at TEXT
        )
    """)

    # 6. CLUSTER MEMBERS
    cursor.execute(f"""
        CREATE TABLE IF NOT EXISTS cluster_members (
            id {pk_def},
            cluster_id INTEGER NOT NULL REFERENCES fraud_clusters(id),
            user_id INTEGER NOT NULL REFERENCES users(id),
            relationship_type TEXT,
            UNIQUE(cluster_id, user_id)
        )
    """)

    # 7. INDEXES
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_ip ON users(ip_address)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_device ON users(device_fingerprint)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_risk ON users(risk_score)")

    connection.commit()
    connection.close()


if __name__ == "__main__":
    init_database()
    engine = get_engine_type()
    target = DATABASE_URL if engine == "postgres" else SQLITE_DB_PATH
    print(f"FraudGuard database initialized using {engine.upper()}.\nTarget: {target}")
