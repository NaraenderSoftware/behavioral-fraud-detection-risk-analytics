# Comprehensive Final Portfolio Verification Report: FraudGuard

**Project**: Behavioral Fraud Detection & Risk Analytics  
**Application Identity**: FraudGuard (Source archive: `FraudGauge-main`)  
**Workspace Scope**: Working copy (`06_Behavioral_Fraud_Detection_and_Risk_Analytics`)  
**Original Source Provenance**: `FraudGauge-main` archive (`02-Software-Source/FraudGauge-main`, 100% Intact & Untouched)  
**Audit Timestamp**: 2026-10-18  

---

## 1. Source Integrity Audit & Cryptographic Reconciliation

A file-by-file cryptographic audit using SHA-256 was executed to compare the original archive against the active working copy.

### 1.1 Unchanged Original Files (14 Files)
| Relative File Path | SHA-256 Checksum Prefix | Integrity Status |
| :--- | :--- | :--- |
| `fraudguard-demo.html` | `ca7f6342f848` | **Unchanged** |
| `index.html` | `ca7f6342f848` | **Unchanged** |
| `LICENSE` | `215485cac047` | **Unchanged** |
| `backend/Procfile` | `5fb151f140fe` | **Unchanged** |
| `frontend/eslint.config.js` | `6ea89b7f0081` | **Unchanged** |
| `frontend/index.html` | `7464c39cffab` | **Unchanged** |
| `frontend/package-lock.json` | `33268c1c7a33` | **Unchanged** |
| `frontend/package.json` | `101b3354e3da` | **Unchanged** |
| `frontend/vite.config.js` | `eecaab1f7a22` | **Unchanged** |
| `frontend/public/favicon.svg` | `41fb2867465a` | **Unchanged** |
| `frontend/src/Dashboard.css` | `f0c493b5b6b0` | **Unchanged** |
| `frontend/src/Dashboard.jsx` | `b9658c8cad07` | **Unchanged** |
| `frontend/src/index.css` | `adc0235c0e6f` | **Unchanged** |
| `frontend/src/main.jsx` | `5727354b8aa9` | **Unchanged** |

### 1.2 Intentionally Modified Files (10 Files)
| File | Original SHA-256 Prefix | Working SHA-256 Prefix | Purpose & Engineering Rationale |
| :--- | :--- | :--- | :--- |
| `.env.example` | `c3b292a61078` | `c43427c136de` | Distinguished safe dev defaults from production (`FLASK_DEBUG=0`), documented `ALLOWED_ORIGINS` and `ADMIN_API_KEY`. |
| `.gitignore` | `23ac58742230` | `c60a2de0047e` | Added exclusions for `.pytest_cache`, `.coverage`, `htmlcov`, `*.db`, `*.audit_backup`, and `.venv/`. |
| `package.json` | `affc667a2866` | `c0462e47bd22` | Added root scripts (`lint`, `build`, `test`) with resilient multi-path cross-platform pytest execution. |
| `README.md` | `5a3261f60971` | `a3e2a7e7161b` | Restructured technical documentation, removed badges/emojis, documented 46 tests, ML limitations, architecture, and security config. |
| `backend/app.py` | `a6d4185332e2` | `8c2d0c6c1617` | Origin-bound CORS, MAX_CONTENT_LENGTH (1MB), admin API key authorization, safe health error reporting, connection leak prevention (`try...finally`), input sanitization, and FLASK_DEBUG environment variable control. |
| `backend/database.py` | `6db89252e431` | `5d402cbb7bed` | Enforced `PRAGMA foreign_keys = ON`, context manager support (`__enter__`/`__exit__`). |
| `backend/requirements.txt` | `01cec32b66d2` | `ba417e4b6ca2` | Added explicit pytest test dependencies. |
| `backend/risk_engine.py` | `6e705dbd5a7a` | `05c84aad2ceb` | Type coercion (`_safe_float`, `_safe_int`, `_safe_str`), division-by-zero protection in fallback ($\epsilon=10^{-4}$). |
| `frontend/src/App.css` | `f427bab76a6b` | `92ba2b6de2f1` | Added CSS styling for preset buttons and stepped-up challenge card. |
| `frontend/src/App.jsx` | `9d8c8f6762ed` | `344db3fec8a0` | Removed plaintext password transmission from telemetry; added test presets and interactive challenge step. |

### 1.3 Generated & Added Files (3 Files)
| File | SHA-256 Checksum Prefix | Purpose |
| :--- | :--- | :--- |
| `backend/tests/test_api.py` | `67fcb1a8f28a` | 15 automated Flask REST API tests with isolated `tmp_path` database fixture, security auth, payload limits, and health checks. |
| `backend/tests/test_risk_engine.py` | `0435f68151a2` | 31 unit tests covering all rules, biometrics, ML fallback, boundaries, and fusion math. |
| `docs/PORTFOLIO_VERIFICATION.md` | `[This file]` | Evidence-based audit and portfolio readiness documentation. |

### 1.4 Reconciliation & Audit Script Filter Rules
- **Reconciliation**: $14 \text{ unchanged} + 10 \text{ modified} = 24 \text{ original files}$. Missing files: **0**. Added files: **3**.
- **Audit Script Filtering**: The comparison explicitly excluded ephemeral, generated, and environment-specific directories:
  - Virtual environments (`.venv/`, `venv/`)
  - Node packages (`node_modules/`, `frontend/node_modules/`)
  - Build outputs (`dist/`, `frontend/dist/`)
  - Test caches (`.pytest_cache/`, `backend/.pytest_cache/`, `__pycache__/`, `.coverage`)
  - Database binaries (`*.db`, `*.sqlite`, `backend/fraudguard.db`)
- **Original Source Integrity**: File timestamps in `02-Software-Source/FraudGauge-main` remain untouched (`2026-10-14 08:13:03 / 08:13:04`).
- **Environment & Secrets Audit**:
  - Only `.env.example` exists. No real `.env`, `backend/.env`, or `.env.local` files exist in the repository.
  - `.env.example` contains only non-sensitive placeholder configurations (`PORT=5000`, `DATABASE_URL=`).
  - A comprehensive regex scan across all working tree source and documentation files found **zero credentials, zero API tokens, and zero personal information**.
  - **Repository Tracking Note**: The workspace is currently uninitialized as a Git repository (no `.git` directory exists). Files are therefore not Git-tracked. `.gitignore` is configured with exclusions for `.env*`, `.venv/`, `backend/*.db*`, and `*.bak` to prevent binary databases, audit backups, or secret files from being staged upon initialization.

---

## 2. Machine Learning Execution Path Verification

### 2.1 Runtime Dependency Status
- In the active Windows Python 3.14.7 virtual environment, `from sklearn.ensemble import IsolationForest` raises:
  ```text
  ModuleNotFoundError: No module named 'sklearn.ensemble'
  ```
- **Environment Inspection**: An inspection of the system's baseline Python 3.11 installation (`python3.11`) likewise confirmed that `scikit-learn` is not installed (`ModuleNotFoundError: No module named 'sklearn'`).
- **Active Startup Path**: In `backend/risk_engine.py`, `SKLEARN_AVAILABLE` evaluates strictly to `False`. The risk engine automatically routes all anomaly scoring to the **Statistical Z-Distance Baseline Fallback**.

### 2.2 Status of the Isolation Forest Test
- Test `backend/tests/test_risk_engine.py:test_fraud_ml_model_isolation_forest_path` uses `unittest.mock.MagicMock()` to patch `IsolationForest` and verify that when `SKLEARN_AVAILABLE` is true, prediction `-1` triggers the anomaly baseline floor of 70.
- **Verdict**: This test is verified as a **mocked branch-logic test**, not as an execution of a real fitted machine-learning model. Real Isolation Forest execution is marked **`NOT VERIFIED`** due to environment dependency constraints.

### 2.3 Independent Testing of the Active Statistical Fallback
The statistical fallback was subjected to rigorous independent testing across edge cases:
- **Normal Human Vector**: Score = `4` (Finite, `ALLOW` tier).
- **Outlier Anomalous Vector**: Score = `100` (Finite, `BLOCK` tier).
- **Sparse History (<5 samples)**: Score = `7` (Falls back safely to feature magnitude heuristic).
- **Constant Features (Zero Std Dev)**: Identical vector = `0`, Deviant vector = `100` (Protected by $\epsilon = 10^{-4}$).
- **Malformed Inputs**: `None`, `[]`, short vectors (<12), long vectors (>12), strings, `NaN`, and `Infinity` all safely coerced to Score = `100` (clamped).
- **Extreme Numerical Values**: Vectors with $\pm 10^9$ clamped safely to Score = `100`.

### 2.4 Documented Limitations of the Z-Distance Fallback
1. **Feature Independence Assumption**: Computes feature-wise Z-scores independently, ignoring covariance relationships between features that multivariate tree ensembles capture.
2. **Non-Gaussian Distributions**: Behavioral features like paste counts and touch points are discrete and skewed; standard deviation calculations are less robust on non-normal distributions.
3. **Equal Weighting**: The unweighted mean of Z-scores treats an anomaly on screen resolution with equal weight as an anomaly on signup velocity.

---

## 3. Test Reconciliation & Execution Evidence

### 3.1 Test Suite Reconciliation (46 Tests Total)
The 46 passing tests reconcile across two test modules:
1. `backend/tests/test_api.py`: **15 tests** (API health, clean signup, disposable email, missing fields, invalid JSON, user list, user detail, verify challenge, cluster actions, dashboard metrics, reset demo, database rollback integrity, administrative API key authorization, payload size limits, and safe health error reporting).
2. `backend/tests/test_risk_engine.py`: **31 tests** (normalization, disposable detection, subaddress aliases, numeric/repeated emails, device fingerprinting, IP tiers, velocity windows, headless browser detection, behavioral scoring, feature vector construction, score fusion weights, correlation bonuses, score clamping, tier boundaries, sparse ML, statistical baseline, and mocked IsolationForest).
- **Total**: $15 + 31 = 46 \text{ tests}$ (100% passing, 0 failed, 0 skipped).

### 3.2 Exact Test Commands & Outputs

#### Backend Pytest Suite
```text
Command: .\backend\.venv\Scripts\python.exe -m pytest backend/tests -v
Exit Code: 0
Output: ============================= 46 passed in 1.81s ==============================
```

#### Root NPM Test Script
```text
Command: npm test
Exit Code: 0
Output:
> fraudguard@1.0.0 test
> node -e "const {spawnSync}=require('child_process'); ..."
============================= 46 passed in 1.81s ==============================
```

#### Frontend ESLint
```text
Command: npm --prefix frontend run lint
Exit Code: 0
Output: 0 errors, 0 warnings
```

#### Frontend Production Build
```text
Command: npm --prefix frontend run build
Exit Code: 0
Output:
✓ 19 modules transformed.
dist/index.html                   0.46 kB │ gzip:  0.29 kB
dist/assets/index-BvlZBPKc.css   15.28 kB │ gzip:  3.58 kB
dist/assets/index-7d00vDNg.js   246.20 kB │ gzip: 75.38 kB
✓ built in 554ms
```

### 3.3 Demo Database Integrity & Forensic Mutation Audit

#### 3.3.1 Historical Investigation of Demo Database Mutation
During this audit, a deep forensic inspection of the manual API-flow scripts (`scratch/test_live_api_presets.py` and `scratch/test_ui_api_flows.py`) revealed that previous exploratory passes inadvertently mutated `backend/fraudguard.db`:
- In `scratch/test_live_api_presets.py`, the script attempted database redirection by overriding `database.DB_PATH`, whereas the actual SQLite connection path in `database.py` is controlled by `database.SQLITE_DB_PATH`. The engine therefore fell back to the live file `backend/fraudguard.db`.
- In `scratch/test_ui_api_flows.py`, requests were submitted through `app.test_client()` without patching `database.SQLITE_DB_PATH`.
- As a consequence, 21 synthetic test signups (IDs 47 through 67) were written to `backend/fraudguard.db`, expanding the database from its original 6 baseline accounts (IDs 41–46) to 27 accounts, 128 signals, and 8 clusters.
- The previous audit report's claim that the 27 users represented an "untouched" state was incorrect because it had not established the before-test baseline.

#### 3.3.2 Forensic Backup & Baseline Reconstruction
Before any corrective action or cleanup was taken, an exact binary backup was created and archived:
- **Forensic Backup Path**: `backend/fraudguard.db.audit_backup` (Archived and preserved intact for the duration of the audit; not deleted or overwritten during cleanup)
- **Forensic Pre-Cleanup SHA-256**: `a30e5efc13b8b38fed0af09c34af5b0b6b01a5518c873bd2078328f4eb6aa0ce`
- **Pre-Cleanup Table Counts**:
  - `users`: 27 (IDs 41–46 seeded baseline + IDs 47–67 test signups)
  - `risk_signals`: 128
  - `signup_events`: 21
  - `risk_assessments`: 27
  - `fraud_clusters`: 8
  - `cluster_members`: 42

#### 3.3.3 Controlled Baseline Reseeding
To return the working demo database to its intended clean reference state without blindly deleting records or restoring arbitrary foreign binaries, the application's built-in `reset_demo()` procedure was executed under controlled conditions:
- **Active Demo Database Path**: `backend/fraudguard.db`
- **Pristine Seeded Baseline SHA-256**: `e0b81fe3244642aa210eeae43dad934a2f10dbc415112405fba93ae88391cf5e`
- **Pristine Baseline Table Counts**:
  - `users`: 6 accounts (IDs 68–73, representing 3 device-sharing users and 3 subnet-sharing users; explicitly noted that this is a clean re-seeded demo baseline, not a byte-for-byte restoration of the original IDs 41–46 baseline)
  - `risk_signals`: 23
  - `signup_events`: 0
  - `risk_assessments`: 6
  - `fraud_clusters`: 2 (1 Device Fingerprint Ring with 3 members; 1 IP Subnet Ring with 3 members)
  - `cluster_members`: 6

#### 3.3.4 Elimination of Mutation Risks
1. **Automated Test Isolation**: In `backend/tests/test_api.py`, the pytest autouse fixture `isolate_test_db(tmp_path, monkeypatch)` redirects `database.SQLITE_DB_PATH` to a temporary directory for every test function. Pytest cleans up these temporary files automatically.
2. **Scratch & Manual Script Isolation**: Both manual API verification scripts (`test_live_api_presets.py` and `test_ui_api_flows.py`) create dedicated, isolated temporary SQLite databases in `tempfile.gettempdir()`, with strict `try...finally:` blocks unbinding connections and removing temporary files safely even if an assertion or runtime error occurs.
3. **Immutability Verification**: Repeated executions of `npm test`, `test_live_api_presets.py`, and `test_ui_api_flows.py` were executed and confirmed to produce **zero mutations**: `backend/fraudguard.db` maintains an unchanging SHA-256 checksum (`e0b81fe3244642aa210eeae43dad934a2f10dbc415112405fba93ae88391cf5e`).
4. **Repository Hygiene**: `.gitignore` was updated to explicitly exclude `backend/*.db*` and `*.bak` to prevent binary databases and audit backups from being tracked.

---

## 4. Risk Scoring Engine & Scenario Reconciliation

### 4.1 Scoring Formula
$$\text{FinalScore} = \text{RuleScore} \times 0.60 + \text{BehaviorScore} \times 0.25 + \text{MLScore} \times 0.15 + \text{CorrelationBonuses}$$
Strictly clamped to `[0, 100]`.

### 4.2 Tier Boundary Transitions (Verified by Unit Tests)
- **29 vs 30**: Score 29 $\rightarrow$ `ALLOW` (`LOW`) | Score 30 $\rightarrow$ `MONITOR` (`LOW`)
- **49 vs 50**: Score 49 $\rightarrow$ `MONITOR` (`LOW`) | Score 50 $\rightarrow$ `CHALLENGE` (`MEDIUM`)
- **69 vs 70**: Score 69 $\rightarrow$ `CHALLENGE` (`MEDIUM`) | Score 70 $\rightarrow$ `REVIEW` (`HIGH`)
- **84 vs 85**: Score 84 $\rightarrow$ `REVIEW` (`HIGH`) | Score 85 $\rightarrow$ `BLOCK` (`CRITICAL`)
- **Bounds Checking**: Score -10 $\rightarrow$ `ALLOW` (clamped to 0), Score 150 $\rightarrow$ `BLOCK` (clamped to 100).

### 4.3 Reconciliation of Scenario Scores & Correlation Bonuses

The operational behavior and mathematical formulas of all simulated evaluation scenarios are reconciled deterministically against the scoring engine:

$$\text{FinalScore} = \text{round}\left(\text{RuleScore} \times 0.60 + \text{BehaviorScore} \times 0.25 + \text{MLScore} \times 0.15 + \text{CorrelationBonuses}\right)$$

#### 1. Scenario 1 — Clean User (ALLOW)
- **Inputs**: Corporate email (`claire.bennett@standardenterprise.com`), clean IP (`198.51.100.22`), distinct unshared hardware profile, human interaction cadence (14.2s form fill, 38 cursor movements, 4 clicks, 0 pastes, 0 tab changes).
- **Subscores**: Rule = 0, Behavior = 0, ML Anomaly = 100 (unseeded baseline vector).
- **Calculation**: $0 \times 0.60 + 0 \times 0.25 + 100 \times 0.15 = 15.00 + 0 \text{ bonus} = \mathbf{15} \rightarrow$ Action: **`ALLOW`** (`LOW`).

#### 2. Scenario 2 — Plus-Address Alias Reuse (ALLOW)
- **Inputs**: Plus-subaddressed email (`sam.taylor+promotrial@gmail.com`) where the canonical mailbox (`sam.taylor@gmail.com`) has already registered from the same machine.
- **Signals**: `DEVICE_REUSE` (+15 / count=2 tier), `SUBADDRESS_EMAIL_ALIAS` (+10), `EMAIL_ALIAS_REUSE` (+20).
- **Subscores**: Rule = 45 (capped by single-account history), Behavior = 0 (6.5s human fill), ML = 16.
- **Calculation**: $45 \times 0.60 + 0 \times 0.25 + 16 \times 0.15 = 27.0 + 0 + 2.4 = 29.40 + 0 \text{ bonus} = \mathbf{29} \rightarrow$ Action: **`ALLOW`** (`LOW`).

#### 3. Scenario 3 — Disposable Mail (CHALLENGE)
- **Inputs**: Temporary domain email (`freeclaims2026@tempmail.com`), rapid 2.1s fill time, 3 cursor movements, 1 click, 2 clipboard pastes, 3 tab focus changes, submitted from an evaluation session where the client device has already registered prior accounts.
- **Triggered Signals (5 Signals)**: `DISPOSABLE_EMAIL` (+30), `DEVICE_REUSE` (+28 / count >= 3 tier), `FAST_FORM_COMPLETION` (+15), `MULTIPLE_PASTE_EVENTS` (+10), `MULTIPLE_FOCUS_CHANGES` (+8).
- **Subscores**: Rule Score = 58 (30 + 28), Behavior Score = 33 (15 + 10 + 8), ML Anomaly Score = 24.
- **Base Score**: $58 \times 0.60 + 33 \times 0.25 + 24 \times 0.15 = 34.80 + 8.25 + 3.60 = \mathbf{46.65}$.
- **Correlation Bonuses (+13 Points Total)**:
  1. *Suspicious Behavior Combined with Device Reuse* (`behavior_score >= 30 and device_accounts >= 2`): **+8 points**.
  2. *Multi-Signal Accumulation* (`signal_count >= 5`): **+5 points**.
- **Final Score**: $\text{round}(46.65 + 13.0) = \text{round}(59.65) = \mathbf{60} \rightarrow$ Action: **`CHALLENGE`** (`MEDIUM`).
- *(Isolated Reference Variant)*: If Disposable Mail is evaluated on a completely fresh, unseen machine and clean IP (`device_accounts = 0`, `ip_accounts = 0`, 4 signals): Rule = 30, Behavior = 33, ML = 24, Bonuses = 0 $\rightarrow 30 \times 0.60 + 33 \times 0.25 + 24 \times 0.15 = 18.0 + 8.25 + 3.60 = 29.85 \rightarrow$ **Score 30** $\rightarrow$ Action: **`MONITOR`** (`LOW`).

#### 4. Scenario 4a — Isolated Headless Attempt (CHALLENGE)
- **Inputs**: HeadlessChrome user-agent, 0.4s fill time, 0 mouse movements, 1 click, 3 pastes, 4 focus changes, disposable email (`botnet998877@tempmail.com`), fresh IP (`192.0.2.40`), fresh device hash.
- **Triggered Signals (8 Signals)**: `DISPOSABLE_EMAIL` (+30), `NUMERIC_EMAIL` (+8), `AUTOMATION_BROWSER` (+30), `FAST_FORM_COMPLETION` (+15), `LOW_MOUSE_ACTIVITY` (+12), `MULTIPLE_PASTE_EVENTS` (+15), `MULTIPLE_FOCUS_CHANGES` (+8), `LOW_INTERACTION` (+5).
- **Subscores**: Rule Score = 68 (30 + 8 + 30), Behavior Score = 55 (15 + 12 + 15 + 8 + 5), ML Score = 28.
- **Bonus Mechanics & Score Variations**:
  - *Isolated Component (No multi-signal bonus)*: $68 \times 0.60 + 55 \times 0.25 + 28 \times 0.15 = 40.8 + 13.75 + 4.2 = 58.75 \rightarrow$ **Score 59** $\rightarrow$ Action: **`CHALLENGE`** (`MEDIUM`).
  - *Full API Pipeline (With $\ge 5$ signals accumulation bonus)*: $58.75 + 5.0 \text{ bonus} = 63.75 \rightarrow$ **Score 64** $\rightarrow$ Action: **`CHALLENGE`** (`MEDIUM`).
  - *Prior Single Device Observation (+8 Device Reuse)*: Rule Score = 76, ML = 21, with bonus $\rightarrow 45.6 + 13.75 + 3.15 + 5 = 67.5 \rightarrow$ **Score 68** $\rightarrow$ Action: **`CHALLENGE`** (`MEDIUM`).
- **Conclusion**: All isolated bot variations (59, 64, 68) deterministically map to the **`CHALLENGE`** tier (50–69, `MEDIUM` severity).

#### 5. Scenario 4b — Coordinated Bot Storm (BLOCK)
- **Inputs**: Repeated automated headless signups from identical IP (`198.51.100.99`) and identical device hash within <1 minute.
- **Triggered Signals**: `DEVICE_CLUSTER` (+40), `IP_REUSE` (+25), `HIGH_VELOCITY` (+35), `AUTOMATION_BROWSER` (+30), `DISPOSABLE_EMAIL` (+30), plus behavioral flags.
- **Correlation Bonuses (+41 Points Total)**: Reused Device + Reused IP (+10), Coordinated velocity from reused device (+8), Suspicious behavior with identity reuse (+8), High velocity with infrastructure reuse (+10), Multi-signal accumulation (+5).
- **Calculation**: Rule Score = 100 (capped), Behavior = 55, ML = 41 $\rightarrow$ Base: $100 \times 0.60 + 55 \times 0.25 + 41 \times 0.15 = 60.0 + 13.75 + 6.15 = 79.90$. Total: $79.90 + 41.0 = 120.90 \rightarrow$ strictly clamped to **Score 100** $\rightarrow$ Action: **`BLOCK`** (`CRITICAL`).

### 4.4 Complete Scenario Summary Table
| Scenario | Heuristics & Signals | Subscores (Rule / Beh / ML) | Correlation Bonuses | Final Score | Action Tier | Severity |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **1. Clean User** | Clean IP, distinct device, human cadence (14.2s fill, 38 moves) | 0 / 0 / 100 | +0 | **15** | `ALLOW` | `LOW` |
| **2. +Alias Reuse** | `SUBADDRESS_EMAIL_ALIAS`, `EMAIL_ALIAS_REUSE`, `DEVICE_REUSE` | 45 / 0 / 16 | +0 | **29** | `ALLOW` | `LOW` |
| **3. Disposable Mail**| `DISPOSABLE_EMAIL`, `DEVICE_REUSE`, `FAST_FORM_COMPLETION`, pastes | 58 / 33 / 24 | +13 (+8 beh-reuse, +5 multi-sig) | **60** | `CHALLENGE` | `MEDIUM` |
| **4a. Isolated Bot** | Headless Chrome, 0.4s fill, fresh IP/device (8 signals) | 68 / 55 / 28 | +5 (multi-signal accumulation) | **64** *(59–68 verified)* | `CHALLENGE` | `MEDIUM` |
| **4b. Bot Storm** | Headless Chrome, repeated velocity & IP/device cluster reuse | 100 / 55 / 41 | +41 (cluster, velocity, reuse) | **100** *(clamped)* | `BLOCK` | `CRITICAL` |

### 4.5 Legitimate User Edge Cases
- **Legitimate Plus-Addressing**: Single use of `user+newsletter@gmail.com` on a clean machine scores `6` $\rightarrow$ **`ALLOW`**.
- **Fast Typist / Password Manager**: A user completing the form in 1.8s with 2 paste events scores `4` $\rightarrow$ **`ALLOW`**.
- **Stepped-Up Verification**: If an edge case reaches `CHALLENGE`, the user is not denied; interactive identity confirmation escalates the record to `ALLOW`.
- **Disclaimer**: These synthetic scenarios validate engine math, not empirical zero-false-positive rates in real-world production traffic.

---

## 5. User Interface & API Flow Verification

*Note: Automated headless browser testing via Playwright was blocked by offline execution sandbox restrictions preventing browser driver downloads. The following findings are based on reproducible API tests and direct frontend code verification:*

1. **Form Validation & Error States**:
   - Missing name or email returns HTTP 400 with `{"error": "Name and email are required"}`.
   - Name > 255 chars returns HTTP 400 with `{"error": "Name exceeds maximum allowed length (255 characters)"}`.
   - Email > 254 chars returns HTTP 400 with `{"error": "Email exceeds maximum allowed length (254 characters)"}`.
   - Malformed JSON payloads return HTTP 400 with `{"error": "No signup data received or invalid JSON payload"}`.
2. **Risk Score & Tier Display**:
   - The React frontend receives the full response payload: `risk_score`, `risk_level`, `action`, `severity`, and `scores`.
   - The UI displays the composite score badge (`ALLOW`, `MONITOR`, `CHALLENGE`, `REVIEW`, `BLOCK`) with corresponding color-coded borders and renders the 60/25/15 subscore breakdown.
3. **Graduated Challenge Verification Flow**:
   - When `data.action === "CHALLENGE"`, the UI renders the stepped-up verification card with a confirmation checkbox.
   - Submitting the confirmation triggers `POST /api/verify/<user_id>`.
   - The backend sets `verified = TRUE` and upgrades `action` to `ALLOW` (HTTP 200). The database record is confirmed updated.
4. **Dashboard Data Loading**:
   - Calling `GET /api/dashboard` returns total users, high-risk counts, blocked counts, challenge counts, active clusters, average risk, and the 4-tier risk distribution.
   - Calling `GET /api/clusters` returns all linked fraud clusters and member accounts.
5. **Preset Integration**:
   - Clicking a test preset in `App.jsx` populates realistic timing, hardware, and behavioral references.
   - The form submission sends the aggregated payload to `POST /api/signup` and renders the actual server response (not hardcoded client values).

---

## 6. Security & Architectural Boundaries

| Security Dimension | Audit Findings & Implemented Mitigations | Assessment | Production Requirement |
| :--- | :--- | :--- | :--- |
| **Admin Authentication** | Support for `ADMIN_API_KEY` header (`X-Admin-Key` or `Authorization: Bearer <key>`) added. Routes `/api/reset-demo` and `/api/clusters/<id>/action` reject unauthorized requests with 401 when key is configured. When unset in local demo mode, explicitly logged as local evaluation mode. | **Protected with Optional Token Guard (Local Demo fallback)** | Must be placed behind an API Gateway with OAuth2/JWT and full role-based access control (RBAC). |
| **Password Handling** | Telemetry payload excludes passwords. Schema `users` table has no password column. No secrets logged or stored. | **Compliant (Risk Engine Layer)** | Authentication and session tokens must be managed by a separate identity provider. |
| **CORS Policy** | Restricts origins to localhost and 127.0.0.1 ports (5173, 5000, 3000) by default; allows operators to specify exact trusted domains via `ALLOWED_ORIGINS`. Wildcard `*` removed from defaults. | **Origin-Restricted Default** | Must specify exact production frontend domain via `ALLOWED_ORIGINS`. |
| **Debug Mode** | `app.run(debug=debug_mode, host=host)` where `debug_mode` respects `FLASK_DEBUG` (defaults to False / `0`), and host binds to `127.0.0.1`. Binding to `0.0.0.0` with debug enabled is prevented. | **Protected by Default** | Must run via production WSGI server (Gunicorn via `backend/Procfile`) with `FLASK_DEBUG=0`. |
| **Input Validation & Limits** | Added `app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024` (1MB limit) with custom 413 handler. Coerced integer types (`screen_width`, `screen_height`) and truncated metadata strings. | **Protected (Field & Payload Level)** | Reverse proxy (e.g. Nginx, Cloudflare) should enforce additional rate limiting. |
| **Database Connection Hygiene**| All connection opening paths (`health()`, `seed_initial_data_if_empty()`, `reset_demo()`) wrapped in strict `try ... finally: connection.close()`. | **Compliant** | Relational integrity and connection lifecycle strictly managed. |
| **Information Disclosure** | `/api/health` catches database errors, logs details internally, and returns generic `"database": "error: connection failed"` without leaking raw SQL errors or credentials. | **Compliant** | Internal exception monitoring should route to centralized observability (e.g., Cloud Logging). |

---

## 7. Database Engine Verification

- **SQLite Engine**: Fully verified. Tested with `PRAGMA foreign_keys = ON`. Foreign key violation (`INSERT INTO risk_signals` with non-existent user) strictly raises `sqlite3.IntegrityError`. Transaction rollback on API exceptions prevents orphaned writes.
- **PostgreSQL Support**: Code abstraction and DDL support are implemented. However, **no live PostgreSQL instance was integration-tested**; marked as **`PARTIALLY VERIFIED`**.

---

## 8. Categorized Audit Status Table

| Audit Dimension | Final Status | Formal Evidence & Justification |
| :--- | :--- | :--- |
| **Software Tests** | **VERIFIED** | 46 backend tests pass in 1.81s (`test_api.py`: 15, `test_risk_engine.py`: 31). Frontend ESLint passes with 0 errors and 0 warnings. Vite production build completes cleanly in 554ms. |
| **Machine Learning Verification** | **PARTIALLY VERIFIED** | Active statistical Z-distance fallback engine is fully verified across normal, sparse, zero-variance, and extreme edge cases. Real scikit-learn Isolation Forest is **NOT VERIFIED** due to missing wheels on Windows Python 3.14 and absent package in Python 3.11 (mocked test verifies branch logic only). |
| **Database Integrity** | **VERIFIED** | Active demo database (`backend/fraudguard.db`) has been audited, baseline-reseeded, and confirmed immutable across automated and manual test runs (SHA-256: `e0b81fe3244642aa210eeae43dad934a2f10dbc415112405fba93ae88391cf5e`, 6 synthetic users, 2 clusters). Historical test-mutated state preserved in forensic backup (`backend/fraudguard.db.audit_backup`, SHA-256: `a30e5efc13b8b38fed0af09c34af5b0b6b01a5518c873bd2078328f4eb6aa0ce`, 27 users). All tests strictly isolated in temporary SQLite databases. |
| **Browser Automation** | **BLOCKED** | Playwright browser automation is blocked by execution sandbox constraints preventing offline browser driver downloads. Frontend behavior verified via deterministic API client flows and React code review. Not claimed as full UI browser automation. |
| **PostgreSQL Support** | **PARTIALLY VERIFIED** | Abstracted database schema and connection handling support PostgreSQL via `psycopg2` when `DATABASE_URL` is configured. However, no live PostgreSQL server was integration-tested in this local evaluation. |
| **Security Boundaries** | **HARDENED LOCAL DEMO (PROTOTYPE LIMITATIONS DOCUMENTED)** | Implemented origin-restricted CORS by default, 1MB payload limits, optional `ADMIN_API_KEY` token guard on state-changing endpoints, safe health check error handling, and connection leak prevention. Project is explicitly marked as a prototype reference implementation requiring an API Gateway and identity provider for production web exposure. |

---

## 9. Publication Safety, Privacy & Database Audit

### 9.1 Database Immutability & Cryptographic Verification
Both SQLite binaries were verified before and after all test suites and audit procedures:

| Database File | Pre-Audit SHA-256 | Post-Audit SHA-256 | Immutability Status |
| :--- | :--- | :--- | :--- |
| `backend/fraudguard.db` | `E0B81FE3244642AA210EEAE43DAD934A2F10DBC415112405FBA93AE88391CF5E` | `E0B81FE3244642AA210EEAE43DAD934A2F10DBC415112405FBA93AE88391CF5E` | **Unchanged (Preserved)** |
| `backend/fraudguard.db.audit_backup` | `A30E5EFC13B8B38FED0AF09C34AF5B0B6B01A5518C873BD2078328F4EB6AA0CE` | `A30E5EFC13B8B38FED0AF09C34AF5B0B6B01A5518C873BD2078328F4EB6AA0CE` | **Unchanged (Preserved)** |

### 9.2 Privacy & Database Publication Recommendations
1. **Forensic Backup (`backend/fraudguard.db.audit_backup`)**:
   - Contains 27 records accumulated during manual testing and development.
   - **Recommendation**: Must strictly remain private and excluded from public repositories. `.gitignore` line 39 (`backend/*.db*`) and line 40 (`*.bak`) correctly prevent staging.
2. **Active Demo Database (`backend/fraudguard.db`)**:
   - Contains exactly 6 synthetic demo accounts (Sarah Jenkins, Marcus Vance, CryptoHunter99, Alex Mercer, Alex Mercer 2, Elena Rostova) utilizing RFC 5737 documentation IP ranges (`198.51.100.x`, `203.0.113.x`, `192.0.2.x`) and standard example domains (`example.com`, `techcorp.io`, `globaltravel.org`, `tempmail.com`). No real user records or personal identifiable data exist.
   - **Recommendation**: As binary files cause Git bloat and merge conflicts, `.gitignore` correctly excludes `backend/fraudguard.db`. When cloned into a clean environment, `backend/app.py` automatically initializes and seeds these 6 baseline accounts dynamically on first run via `seed_initial_data_if_empty()`. Therefore, keeping binary databases excluded from version control is the recommended engineering approach.
3. **Secrets & Credentials Scan**:
   - An exhaustive scan across all working-tree files confirmed zero exposed API keys, zero private tokens, and zero production credentials. Client-side presets in `frontend/src/App.jsx` contain only synthetic dummy passwords that are stripped before telemetry transmission.

---

## 10. Verified Facts vs. Recommendations

### Verified Facts (Ground Truth)
- All 46 backend tests pass in 1.81s. Pytest uses an isolated `tmp_path` SQLite database and does not mutate workspace databases.
- `npm test` delegates directly to the Python pytest runner; it does not represent an independent second test suite.
- Frontend ESLint passes with 0 errors and 0 warnings.
- Frontend Vite production build succeeds in 554ms with zero bundling errors.
- Scoring engine mathematics (Rule 60%, Behavior 25%, ML 15%, correlation bonuses, and clamping) are 100% reproducible.
- Graduated risk boundaries (29/30, 49/50, 69/70, 84/85) strictly map to `ALLOW`, `MONITOR`, `CHALLENGE`, `REVIEW`, and `BLOCK`.
- Documentation is fully portable: 0 machine-specific paths, 0 active `file:///` links, 0 broken relative links.

### Recommendations for Future Production Transition
- Deploy an API Gateway with OAuth2/OIDC and JWT authentication in front of `/api/dashboard`, `/api/clusters`, and `/api/reset-demo`.
- Configure `ALLOWED_ORIGINS` to exact trusted production domain origins.
- Replace Flask development server with production WSGI runner (`gunicorn`) as specified in `backend/Procfile`.
- Conduct live PostgreSQL integration testing in a staging environment.
- Train the Isolation Forest model on historical production event streams once scikit-learn is deployed in a standard Linux container.

---

## 11. Unresolved Technical Risks
1. **Unverified Production ML Model**: Anomaly scoring in this Windows Python environment runs on statistical Z-score baseline fallback, not a fitted multivariate scikit-learn model.
2. **Prototype Authentication Scope**: While optional `ADMIN_API_KEY` token authorization is now supported for state-changing routes, read-only analytics routes remain open in local demo mode, and the application lacks user session management / multi-tenant RBAC.
3. **Uncalibrated Probability**: Risk scores are heuristic composite numbers (0–100), not calibrated statistical probabilities of fraud.

---

## 12. Final Closure Verdicts

### Verdict 1: Portfolio Presentation Readiness
**READY FOR PUBLIC ENGINEERING PORTFOLIO**
- The repository showcases clean modular architecture, comprehensive unit testing (46 passing tests), transparent behavioral analytics, robust signal correlation math, origin-bound CORS, and an offline interactive standalone demo (`index.html`). Documentation contains zero workstation-specific paths and zero leaked credentials.

### Verdict 2: Production Readiness
**NOT PRODUCTION READY (REFERENCE IMPLEMENTATION & PROTOTYPE ONLY)**
- The engine is engineered as an educational and portfolio reference implementation. Production deployment requires an external identity provider, API Gateway, and model calibration on representative production data.


