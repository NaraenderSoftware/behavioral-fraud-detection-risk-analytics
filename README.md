# FraudGuard: Behavioral Fraud Detection and Risk Analytics

## Overview

FraudGuard is a prototype software system designed to detect and mitigate multi-account abuse, promotional fraud, and automated signup attacks in zero-payment onboarding environments. In scenarios such as free trial registrations, promotional credits, and onboarding tiers, traditional payment-gateway validation (such as credit card checks or billing address verification) is unavailable. FraudGuard addresses this gap by evaluating passive client-side behavioral biometrics, device hardware characteristics, IP velocity heuristics, email normalization patterns, and anomaly scoring to produce an explainable 0–100 composite risk score and enforce a five-tier graduated action decision.

## Problem Statement

When digital platforms offer free trials, signup credits, or promotional bonuses without requiring payment information, they are frequently targeted by Sybil attacks—users creating multiple accounts to exploit benefits repeatedly. Common defenses have notable weaknesses:

- Requiring a credit card creates high onboarding friction and reduces legitimate conversion.
- Outright IP-based blocking generates high false-positive rates for legitimate users sharing institutional networks, university campuses, corporate proxies, or mobile carrier NAT pools.
- Purely reactive manual review does not scale during coordinated signup spikes.

## Project Objectives

1. Develop a multi-layer risk scoring pipeline combining deterministic heuristics, behavioral telemetry, and anomaly scoring.
2. Provide a graduated decision framework (`ALLOW`, `MONITOR`, `CHALLENGE`, `REVIEW`, `BLOCK`) rather than binary access denial.
3. Graph and correlate accounts into fraud clusters based on shared hardware fingerprints and network identifiers.
4. Provide a stepped-up interactive verification flow to allow legitimate users flagged by network sharing to confirm their identity.
5. Offer a completely offline, zero-dependency standalone demonstration for immediate evaluation without requiring local server or database setup.

## Main Features

- Passive behavioral telemetry tracking: Form completion duration, mouse cursor movement counts, clipboard paste operations, and browser tab visibility changes.
- Email intelligence: Mailbox normalization (stripping subaddress aliases and Gmail periods), disposable email domain detection, username numeric density checks, and repeated character analysis.
- Device and network fingerprinting: Deterministic SHA-256 device fingerprinting based on screen resolution, timezone, user-agent, hardware concurrency, and touch points, combined with IP reuse tracking.
- Signup velocity monitoring: Sliding five-minute window tracking signup attempts per network address.
- Composite risk scoring: Weighted fusion combining 60% deterministic rules, 25% behavioral biometrics, and 15% anomaly scoring, supplemented by multi-signal correlation bonuses.
- Five-tier graduated decision engine: Maps scores to `ALLOW` (0–29), `MONITOR` (30–49), `CHALLENGE` (50–69), `REVIEW` (70–84), and `BLOCK` (85–100).
- Interactive verification flow: Stepped-up confirmation step for `CHALLENGE` tier accounts that updates their database status to `ALLOW` upon completion.
- Automated fraud clustering: Automatically identifies and groups accounts sharing identical device fingerprints or IP addresses into cluster rings with administrative status controls (`ACTIVE`, `FLAGGED`, `RESTRICTED`).
- Dual database compatibility: Uses local SQLite by default with foreign-key enforcement, with PostgreSQL connection support via the `DATABASE_URL` environment variable.
- Standalone offline demo: Fully functional browser-based mock interface in a single HTML file requiring no external libraries or backend connection.

## System Architecture

```mermaid
flowchart TD
    subgraph Client ["Client Browser (Onboarding Flow)"]
        A[User Signup Form]
        B[Passive Behavioral Telemetry<br/>Form Fill Speed, Mouse Moves, Pastes, Tab Switches]
        C[Device Environment Fingerprinting<br/>Screen, Timezone, User-Agent, Hardware Concurrency]
        A -->|Form Submit| D[Payload Assembly]
        B --> D
        C --> D
    end

    subgraph Backend ["Backend API (Flask / backend/app.py)"]
        D -->|POST /api/signup| E[Input Validation & Header Parsing]
        
        subgraph RiskEngine ["Risk Engine (backend/risk_engine.py)"]
            E --> R1[Email Analysis<br/>Disposable Check & Alias Normalization]
            E --> R2[Device & IP History Lookup]
            E --> R3[Signup Velocity Check]
            E --> R4[User-Agent & Automation Detection]
            E --> R5[Behavioral Telemetry Scoring]
            E --> R6[ML Anomaly Detector<br/>IsolationForest or Statistical Z-Score Fallback]
            
            R1 & R2 & R3 & R4 & R5 & R6 --> F[Score Fusion & Correlation Bonuses]
        end

        F --> G{5-Tier Decision Logic}
        G -->|0 - 29| H[ALLOW]
        G -->|30 - 49| I[MONITOR]
        G -->|50 - 69| J[CHALLENGE<br/>Stepped-Up Verification]
        G -->|70 - 84| K[REVIEW<br/>Analyst Audit Queue]
        G -->|85 - 100| L[BLOCK<br/>Deny Account Creation]

        F --> M[Cluster Graph Synchronization]
    end

    subgraph Storage ["Database Layer (backend/database.py)"]
        M --> DB[(SQLite / PostgreSQL)]
        DB --- T1[users]
        DB --- T2[risk_signals]
        DB --- T3[signup_events]
        DB --- T4[risk_assessments]
        DB --- T5[fraud_clusters]
        DB --- T6[cluster_members]
    end

    subgraph Admin ["Admin Console (React Frontend)"]
        DB -->|GET /api/dashboard| N[Threat Distribution & KPIs]
        DB -->|GET /api/users| O[User Audit List & Details]
        DB -->|GET /api/clusters| P[Cluster Ring Manager]
    end
```

### Execution Flow

1. The client completes the signup form (`App.jsx`). Passive event listeners track form completion duration, mouse movement counts, clipboard paste events, and tab focus changes.
2. The client submits a JSON payload to `POST /api/signup` containing form values and telemetry. Passwords entered in the form are excluded from the telemetry payload.
3. The Flask API (`backend/app.py`) parses the payload and queries the database for historical counts associated with the device fingerprint, client IP, and normalized email.
4. The risk engine (`backend/risk_engine.py`) evaluates the deterministic rules, calculates the behavioral score, constructs a 12-dimensional feature vector, and runs anomaly scoring.
5. Base scores are fused using weighted contributions (60% rule, 25% behavior, 15% anomaly) and adjusted by multi-signal correlation bonuses.
6. The composite score maps to one of five graduated action tiers (`ALLOW`, `MONITOR`, `CHALLENGE`, `REVIEW`, `BLOCK`).
7. User records, individual triggered risk signals, velocity timestamps, and assessment audit trails are persisted within an atomic database transaction. If the account shares a device or IP with prior accounts, cluster records are updated.
8. The client receives the evaluation response and displays the score breakdown and action badge. If the action is `CHALLENGE`, an interactive verification checkbox is presented.

## Risk-Scoring Approach

The composite risk score is calculated using a multi-layer formula:

$$\text{BaseScore} = (\text{RuleScore} \times 0.60) + (\text{BehaviorScore} \times 0.25) + (\text{MLScore} \times 0.15)$$

$$\text{FinalScore} = \min(100, \max(0, \text{round}(\text{BaseScore} + \text{CorrelationBonuses})))$$

### Correlation Bonuses

When multiple independent detection signals correlate, FraudGuard applies additional risk points to reflect compounding threat indicators:

- Reused device and reused IP (`device_accounts >= 2` and `ip_accounts >= 2`): +10 points
- Coordinated velocity from a reused device (`recent_signups >= 2` and `device_accounts >= 2`): +8 points
- Suspicious behavior combined with identity reuse (`behavior_score >= 30` and (`device_accounts >= 2` or `ip_accounts >= 3`)): +8 points
- High velocity combined with infrastructure reuse (`recent_signups >= 3` and (`device_accounts >= 2` or `ip_accounts >= 3`)): +10 points
- Multi-signal accumulation (`signal_count >= 5`): +5 points

### Graduated Decision Tiers

| Score Range | Action Tier | Severity | Operational Response |
| :--- | :--- | :--- | :--- |
| 0 – 29 | `ALLOW` | `LOW` | Account creation proceeds without restriction. |
| 30 – 49 | `MONITOR` | `LOW` | Account is created but marked for passive velocity and event monitoring. |
| 50 – 69 | `CHALLENGE` | `MEDIUM` | Account requires stepped-up verification (e.g., self-confirmation checkbox or email token). Upon verification, status updates to `ALLOW`. |
| 70 – 84 | `REVIEW` | `HIGH` | Account is placed in a manual fraud analyst queue for administrative review before privileges are granted. |
| 85 – 100 | `BLOCK` | `CRITICAL` | Account creation is prevented under anti-abuse policies. |

Note: The risk score is an empirical, heuristic composite index on a 0–100 scale. It is not a calibrated statistical probability of fraud.

## Detection Signals

The engine implements the following detection heuristics in `backend/risk_engine.py`:

| Signal Identifier | Severity | Points | Trigger Condition |
| :--- | :--- | :--- | :--- |
| `DISPOSABLE_EMAIL` | `HIGH` | +30 | Email domain matches a recognized temporary or disposable mail provider. |
| `SUBADDRESS_EMAIL_ALIAS` | `MEDIUM` | +10 | Email uses plus-addressing (e.g., `name+promo@gmail.com`). |
| `EMAIL_ALIAS_REUSE` | `HIGH` | +20 | Canonical normalized email matches an already registered user account. |
| `NUMERIC_EMAIL` | `MEDIUM` | +8 | Local part of email address contains 5 or more digits. |
| `REPEATED_EMAIL_PATTERN` | `LOW` | +5 | Local part contains 3 or more consecutive identical characters. |
| `INVALID_EMAIL` | `HIGH` | +25 | Email format is invalid or exceeds 254 characters. |
| `DEVICE_CLUSTER` | `CRITICAL` | +40 | Device fingerprint is already associated with 5 or more accounts. |
| `DEVICE_REUSE` | `LOW` to `HIGH` | +8 to +28 | Device fingerprint is already associated with 1 to 4 accounts. |
| `MISSING_DEVICE_FINGERPRINT` | `MEDIUM` | +10 | Client submitted without a valid device fingerprint string. |
| `IP_CLUSTER` | `CRITICAL` | +35 | Client IP address is already associated with 8 or more accounts. |
| `IP_REUSE` | `LOW` to `HIGH` | +8 to +25 | Client IP address is already associated with 2 to 7 accounts. |
| `MISSING_IP_ADDRESS` | `MEDIUM` | +10 | Client IP address could not be resolved from socket or proxy headers. |
| `HIGH_VELOCITY` / `SIGNUP_VELOCITY` | `MEDIUM` to `CRITICAL` | +10 to +35 | 2 or more signups recorded from the same IP within a rolling 5-minute window. |
| `AUTOMATION_BROWSER` | `CRITICAL` | +30 | User-agent string indicates Headless Chrome, Selenium, Playwright, or Puppeteer. |
| `MISSING_USER_AGENT` | `MEDIUM` | +10 | Client user-agent string is empty or absent. |
| `FAST_FORM_COMPLETION` | `LOW` or `HIGH` | +5 or +15 | Total form fill duration is below 5.0s (+5) or below 2.5s (+15). |
| `LOW_MOUSE_ACTIVITY` | `MEDIUM` | +12 | 2 or fewer mouse movement events recorded during the session. |
| `MULTIPLE_PASTE_EVENTS` | `MEDIUM` or `HIGH` | +10 or +15 | Clipboard paste count is 2 (+10) or 3 or more (+15). |
| `MULTIPLE_FOCUS_CHANGES` | `MEDIUM` or `HIGH` | +8 or +12 | Page visibility/tab changes count is 3 to 5 (+8) or 6 or more (+12). |
| `LOW_INTERACTION` | `LOW` | +5 | Compound indicator: 1 or fewer clicks combined with 2 or fewer mouse movements. |

## Technology Stack

- **Backend**: Python 3, Flask, Flask-CORS, SQLite3, psycopg2-binary (optional PostgreSQL connection), scikit-learn (optional Isolation Forest dependency).
- **Frontend**: React 19, Vite 8, Vanilla CSS.
- **Testing**: pytest (backend unit and API tests), ESLint (frontend static analysis).
- **Standalone Demos**: HTML5, Vanilla JavaScript, CSS3 (zero external dependencies).

## Project Structure

```text
06_Behavioral_Fraud_Detection_and_Risk_Analytics/
├── .env.example              # Sample environment configuration template
├── .gitignore                # Git exclusions (build artifacts, databases, venvs)
├── index.html                # Standalone offline browser demonstration
├── fraudguard-demo.html      # Standalone offline demo (identical descriptive alias)
├── LICENSE                   # MIT License
├── package.json              # Root npm scripts for dev, build, lint, and test
├── README.md                 # Technical project documentation
├── backend/
│   ├── app.py                # Flask REST API endpoints and application lifecycle
│   ├── database.py           # SQLite / PostgreSQL schema initialization and connection wrappers
│   ├── Procfile              # Production WSGI deployment specification
│   ├── requirements.txt      # Python dependencies
│   ├── risk_engine.py        # Rule engine, behavioral scoring, and anomaly detection model
│   └── tests/
│       ├── test_api.py       # API integration tests with isolated temporary SQLite fixture
│       └── test_risk_engine.py # Unit tests for rules, scoring math, boundaries, and ML fallback
├── docs/
│   └── PORTFOLIO_VERIFICATION.md # Technical verification report and forensic audit log
└── frontend/
    ├── eslint.config.js      # Frontend ESLint configuration
    ├── index.html            # Vite HTML entry point
    ├── package.json          # Frontend dependencies and build scripts
    ├── package-lock.json     # Locked frontend dependency tree
    ├── vite.config.js        # Vite build configuration
    ├── public/
    │   └── favicon.svg       # Application favicon
    └── src/
        ├── App.css           # Signup view styles and theme variables
        ├── App.jsx           # Signup form, telemetry listeners, and presets
        ├── Dashboard.css     # Admin console layout and card styles
        ├── Dashboard.jsx     # Admin metrics, timeline, and cluster management
        ├── index.css         # Base stylesheet
        └── main.jsx          # React application root
```

## Installation and Setup

### Prerequisites

- Python 3.10 or higher
- Node.js 18 or higher and npm

### 1. Backend Setup

From the repository root:

```bash
# Navigate to backend directory
cd backend

# Create a virtual environment
python -m venv .venv

# Activate the virtual environment
# On Windows PowerShell:
.\.venv\Scripts\Activate.ps1
# On macOS / Linux:
source .venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt
```

### 2. Frontend Setup

From the repository root:

```bash
# Navigate to frontend directory
cd frontend

# Install Node dependencies
npm install
```

### 3. Environment Configuration

Copy the sample environment file if custom configuration is needed:

```bash
# From repository root
cp .env.example .env
```

By default, leaving `DATABASE_URL` empty instructs the backend to use the local SQLite database at `backend/fraudguard.db`. To connect to PostgreSQL, set:

```text
DATABASE_URL=postgresql://username:password@localhost:5432/fraudguard
```

## Running the Application

### Starting the Backend

From the `backend/` directory with your virtual environment activated:

```bash
python app.py
```

The Flask API will start at `http://127.0.0.1:5000`. On first launch, it automatically initializes database tables and seeds reference demonstration accounts if the database is empty.

### Starting the Frontend

In a separate terminal, from the `frontend/` directory (or from root via `npm run dev`):

```bash
cd frontend
npm run dev
```

The Vite development server will start at `http://localhost:5173`. Open this URL in a browser to access the onboarding form and admin console.

## Running Tests

### Running Backend Tests

Backend tests use pytest with an isolated temporary database fixture, ensuring test runs do not mutate the local working database.

From the repository root using the npm script:

```bash
npm test
```

Or directly using Python in the virtual environment:

```bash
# On Windows PowerShell:
.\backend\.venv\Scripts\python.exe -m pytest backend/tests -v

# On macOS / Linux:
./backend/.venv/bin/python -m pytest backend/tests -v
```

The backend test suite consists of 46 tests:
- `backend/tests/test_api.py`: 15 tests covering API endpoints, input validation, user detail retrieval, challenge verification, cluster actions, dashboard metrics, reset procedures, database rollback integrity, administrative API key authorization, payload size limits (1 MB), and safe health check error handling.
- `backend/tests/test_risk_engine.py`: 31 tests covering email normalization, disposable email detection, subaddressing, device fingerprinting, IP reuse tiers, velocity checks, user-agent parsing, behavioral scoring, feature vector construction, score fusion weights, correlation bonuses, tier boundaries, and anomaly model fallback logic.

### Running Frontend Verification

From the repository root:

```bash
# Lint frontend source code
npm run lint

# Build production bundle
npm run build
```

## Standalone Demo Instructions

The repository includes two standalone demo files in the root folder: `index.html` and `fraudguard-demo.html`. These files are identical byte-for-byte duplicates preserved for user convenience:
- `index.html` enables direct serving when hosted via static web hosts or GitHub Pages.
- `fraudguard-demo.html` provides a descriptive filename for repository browsing.

### Running the Standalone Demo

1. Open `index.html` or `fraudguard-demo.html` directly in any standard browser (Chrome, Edge, Firefox, Safari).
2. The demo runs entirely in the browser using client-side JavaScript (`file:///` protocol). It requires no backend server, no npm installation, no database, and no network connection.
3. The demo interface includes pre-loaded sample accounts, an attack simulation sandbox, and test presets (`Clean User`, `+Alias Reuse`, `Disposable Mail`, `Bot Attack`) to evaluate how signals trigger risk score changes and graduated decisions offline.

## Limitations and Security Considerations

1. **Machine Learning Model Scope**:
   - `backend/risk_engine.py` contains an `IsolationForest` code path that trains on a 12-dimensional numerical vector.
   - However, when `scikit-learn` is not installed in the environment (e.g., Python 3.14 on Windows where pre-compiled wheels may be unavailable) or when fewer than 10 historical records exist, the engine falls back to an internal statistical Z-distance baseline heuristic.
   - The test suite includes a test (`test_fraud_ml_model_isolation_forest_path`) that verifies the branch logic using a mock (`unittest.mock.MagicMock`). Real execution of a trained Isolation Forest model is not verified in the audited Python 3.14 environment.
   - FraudGuard has been evaluated against synthetic scenarios and simulated attack vectors; no real-world accuracy, precision, recall, or F1 scores on labeled production fraud data are claimed.
2. **Administrative Endpoint Authorization**:
   - State-changing administrative endpoints (`/api/reset-demo`, `/api/clusters/<id>/action`) support token authentication via `X-Admin-Key` or `Authorization: Bearer <key>` when `ADMIN_API_KEY` is configured in the environment.
   - In zero-config local demo mode (when `ADMIN_API_KEY` is unset), administrative routes remain accessible without credentials for local evaluation convenience.
   - For production deployment, administrative endpoints must be placed behind an API gateway with OAuth2/OIDC and role-based access control (RBAC).
3. **CORS and Debug Mode**:
   - The Flask backend restricts allowed origins to local development URLs (`http://localhost:5173`, `http://127.0.0.1:5173`, etc.) by default and allows explicit origin domain configuration via `ALLOWED_ORIGINS`.
   - In `app.py`, debug mode respects `FLASK_DEBUG` (defaulting to False/`0`) and binds to `127.0.0.1`. In production, the application must be served using a production WSGI server (such as Gunicorn as defined in `backend/Procfile`).
4. **Telemetry and Privacy Boundary**:
   - Passwords entered in the signup form are handled by the client form state but are intentionally excluded from the telemetry payload sent to `/api/signup`. The risk engine never receives, logs, or stores passwords.
   - Clipboard text contents are not inspected; only the numerical count of paste events is tracked.
   - Keystroke text is not logged; only field lengths, form completion time, and mouse movement counts are recorded.
5. **Database Engine Testing**:
   - The local SQLite implementation is verified with foreign-key constraints enabled.
   - While database abstraction and DDL support for PostgreSQL are implemented in `backend/database.py`, live integration testing against a running PostgreSQL server was not performed during local evaluation.

## Future Improvements

- Add JWT-based authentication and role-based access control (RBAC) to administrative and monitoring endpoints.
- Introduce API rate limiting (e.g., using Flask-Limiter or reverse-proxy rate limiting) to prevent endpoint abuse.
- Train and evaluate the unsupervised Isolation Forest model on historical event datasets in an environment with pre-built wheel support (such as a standard Linux container).
- Implement live PostgreSQL integration test suites in automated CI pipelines.
- Calibrate composite risk scores against labeled fraud datasets using logistic regression or Platt scaling to provide true posterior probabilities.

## License

This project is licensed under the [MIT License](LICENSE).
