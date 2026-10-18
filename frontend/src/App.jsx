import { useEffect, useRef, useState } from "react";
import "./App.css";
import Dashboard from "./Dashboard";

// Backend URL: set VITE_API_URL in your hosting provider's env vars
// (e.g. Vercel) once the Flask backend is deployed. Falls back to
// localhost for local development.
const API_BASE = import.meta.env.VITE_API_URL || "http://127.0.0.1:5000";

function App() {
  const [showDashboard, setShowDashboard] = useState(false);
  const [formData, setFormData] = useState({
    name: "",
    email: "",
    password: "",
  });

  const [message, setMessage] = useState("");
  const [analysis, setAnalysis] = useState(null);
  const [loading, setLoading] = useState(false);
  const [verifying, setVerifying] = useState(false);
  const [verified, setVerified] = useState(false);
  const [verifyChecked, setVerifyChecked] = useState(false);
  const [activePreset, setActivePreset] = useState(null);

  // ---------------------------------------------------------
  // Behavioral telemetry tracking
  // ---------------------------------------------------------

  const pageStartTime = useRef(null);
  const mouseMovements = useRef(0);
  const clickCount = useRef(0);
  const pasteCount = useRef(0);
  const focusChanges = useRef(0);

  useEffect(() => {
    pageStartTime.current = Date.now();

    const handleMouseMove = () => {
      mouseMovements.current += 1;
    };

    const handleClick = () => {
      clickCount.current += 1;
    };

    const handlePaste = () => {
      pasteCount.current += 1;
    };

    const handleVisibilityChange = () => {
      focusChanges.current += 1;
    };

    window.addEventListener("mousemove", handleMouseMove);
    window.addEventListener("click", handleClick);
    window.addEventListener("paste", handlePaste);
    document.addEventListener("visibilitychange", handleVisibilityChange);

    return () => {
      window.removeEventListener("mousemove", handleMouseMove);
      window.removeEventListener("click", handleClick);
      window.removeEventListener("paste", handlePaste);
      document.removeEventListener("visibilitychange", handleVisibilityChange);
    };
  }, []);

  // ---------------------------------------------------------
  // Synthetic Presets (Demonstration & Verification)
  // ---------------------------------------------------------

  const applyPreset = (presetKey) => {
    setActivePreset(presetKey);
    setMessage("");
    setAnalysis(null);
    setVerified(false);
    setVerifyChecked(false);

    if (presetKey === "clean") {
      setFormData({
        name: "Claire Bennett",
        email: "claire.bennett@standardenterprise.com",
        password: "SecurePassword2026!",
      });
      pageStartTime.current = Date.now() - 14200; // Simulated 14.2s fill
      mouseMovements.current = 38;
      clickCount.current = 4;
      pasteCount.current = 0;
      focusChanges.current = 0;
    } else if (presetKey === "alias") {
      setFormData({
        name: "Sam Taylor",
        email: "sam.taylor+promotrial@gmail.com",
        password: "TrialPassword123!",
      });
      pageStartTime.current = Date.now() - 6500; // 6.5s
      mouseMovements.current = 14;
      clickCount.current = 2;
      pasteCount.current = 1;
      focusChanges.current = 1;
    } else if (presetKey === "disposable") {
      setFormData({
        name: "BonusHunter99",
        email: "freeclaims2026@tempmail.com",
        password: "Pass" + Math.floor(Math.random() * 9000),
      });
      pageStartTime.current = Date.now() - 2100; // 2.1s
      mouseMovements.current = 3;
      clickCount.current = 1;
      pasteCount.current = 2;
      focusChanges.current = 3;
    } else if (presetKey === "bot") {
      setFormData({
        name: "Automated_Instance_07",
        email: "botnet998877@tempmail.com",
        password: "pwd" + Date.now(),
      });
      pageStartTime.current = Date.now() - 800; // 0.8s
      mouseMovements.current = 0;
      clickCount.current = 1;
      pasteCount.current = 3;
      focusChanges.current = 5;
    }
  };

  // ---------------------------------------------------------
  // Form change
  // ---------------------------------------------------------

  const handleChange = (e) => {
    setActivePreset(null);
    setFormData({
      ...formData,
      [e.target.name]: e.target.value,
    });
  };

  // ---------------------------------------------------------
  // Signup evaluation
  // ---------------------------------------------------------

  const handleSubmit = async (e) => {
    e.preventDefault();

    setLoading(true);
    setMessage("");
    setAnalysis(null);
    setVerified(false);
    setVerifyChecked(false);

    const formFillTime = Math.max(0.5, (Date.now() - pageStartTime.current) / 1000);

    // Notice: Sensitive password is intentionally excluded from risk telemetry payload
    const payload = {
      name: formData.name,
      email: formData.email,

      // Device parameters
      screen_width: window.screen.width,
      screen_height: window.screen.height,
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC",
      user_agent: activePreset === "bot"
        ? "Mozilla/5.0 (Windows NT 10.0; Win64; x64) HeadlessChrome/120.0"
        : navigator.userAgent,
      hardware_concurrency: navigator.hardwareConcurrency || 4,
      max_touch_points: navigator.maxTouchPoints || 0,

      // Passive behavioral telemetry
      form_fill_time: formFillTime,
      mouse_movements: mouseMovements.current,
      click_count: clickCount.current,
      paste_count: pasteCount.current,
      focus_changes: focusChanges.current,

      signup_time: new Date().toISOString(),
    };

    try {
      const response = await fetch(API_BASE + "/api/signup", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      const data = await response.json();

      if (response.ok) {
        setAnalysis(data);

        if (data.action === "BLOCK") {
          setMessage("⚠ High anomaly risk detected. Signup blocked under anti-abuse policy.");
        } else if (data.action === "REVIEW") {
          setMessage("⚠ Elevated threat score. Account pending manual fraud analyst review.");
        } else if (data.action === "CHALLENGE") {
          setMessage("Additional identity confirmation required to verify promotional eligibility.");
        } else if (data.action === "MONITOR") {
          setMessage("Account created. Flagged for passive velocity monitoring.");
        } else {
          setMessage("✓ Account created successfully! Risk profile clean (ALLOW).");
        }
      } else {
        setMessage(`⚠ ${data.error || "Signup evaluation failed"}`);
      }
    } catch (error) {
      console.error(error);
      setMessage("⚠ Cannot connect to FraudGuard backend server at " + API_BASE);
    } finally {
      setLoading(false);
    }
  };

  // ---------------------------------------------------------
  // Verification (graduated response for CHALLENGE tier)
  // ---------------------------------------------------------

  const handleVerify = async () => {
    if (!analysis || !verifyChecked) return;

    setVerifying(true);

    try {
      await new Promise((resolve) => setTimeout(resolve, 800));

      const response = await fetch(`${API_BASE}/api/verify/${analysis.user_id}`, {
        method: "POST",
      });

      if (response.ok) {
        setVerified(true);
        setMessage("✓ Verification complete! Account action escalated to ALLOW.");
      } else {
        setMessage("⚠ Verification failed. Please contact support.");
      }
    } catch (error) {
      console.error(error);
      setMessage("⚠ Cannot connect to FraudGuard backend.");
    } finally {
      setVerifying(false);
    }
  };

  return (
    <div className="app">
      <div className="background-grid"></div>

      <header className="navbar">
        <div className="logo">
          <span className="logo-icon">F</span>
          FRAUD<span>GUARD</span>
        </div>

        <div className="nav-status">
          <span className="status-dot"></span>
          PROTECTION ACTIVE
        </div>

        <button
          className="dashboard-button"
          onClick={() => setShowDashboard(!showDashboard)}
        >
          {showDashboard ? "← BACK TO SIGNUP" : "ADMIN CONSOLE →"}
        </button>
      </header>

      {showDashboard ? (
        <Dashboard />
      ) : (
        <main className="main-content">
          <section className="hero">
            <div className="badge">BEHAVIORAL FRAUD & RISK ANALYTICS</div>
            <h1>
              Zero-Payment <span>Abuse Prevention</span>
            </h1>
            <p>
              Protect SaaS free trials and promotional bonus tiers from coordinated
              multi-account abuse without requiring credit card gateways. Evaluates passive
              behavioral biometrics, device environment hashes, and velocity heuristics.
            </p>

            <div className="privacy-card">
              <div className="privacy-title">🔒 PRIVACY & RESPONSIBLE TELEMETRY</div>
              <p>
                FraudGuard analyzes passive cadence (form timing, mouse entropy) and hardware
                parameters. Passwords, keystroke text, and personal clipboard contents are never
                logged or retained. Risk scores serve as automated decision support, not proof of wrongdoing.
              </p>
            </div>
          </section>

          <section className="signup-card">
            <div className="card-header">
              <div>
                <h2>Account Evaluation</h2>
                <p>Submit profile to run multi-layer fraud scoring</p>
              </div>
              <div className="shield">🛡️</div>
            </div>

            {/* Synthetic Presets for immediate interactive verification */}
            <div className="presets-bar">
              <span className="presets-label">TEST PRESETS (DEMO):</span>
              <div className="presets-buttons">
                <button
                  type="button"
                  className={`preset-pill ${activePreset === "clean" ? "active" : ""}`}
                  onClick={() => applyPreset("clean")}
                >
                  Clean User
                </button>
                <button
                  type="button"
                  className={`preset-pill ${activePreset === "alias" ? "active" : ""}`}
                  onClick={() => applyPreset("alias")}
                >
                  +Alias Reuse
                </button>
                <button
                  type="button"
                  className={`preset-pill ${activePreset === "disposable" ? "active" : ""}`}
                  onClick={() => applyPreset("disposable")}
                >
                  Disposable Mail
                </button>
                <button
                  type="button"
                  className={`preset-pill ${activePreset === "bot" ? "active" : ""}`}
                  onClick={() => applyPreset("bot")}
                >
                  Bot / Automation
                </button>
              </div>
            </div>

            <form onSubmit={handleSubmit}>
              <div className="form-group">
                <label>FULL NAME</label>
                <input
                  type="text"
                  name="name"
                  placeholder="e.g. Alex Morgan"
                  value={formData.name}
                  onChange={handleChange}
                  required
                />
              </div>

              <div className="form-group">
                <label>EMAIL ADDRESS</label>
                <input
                  type="email"
                  name="email"
                  placeholder="e.g. user@example.com"
                  value={formData.email}
                  onChange={handleChange}
                  required
                />
              </div>

              <div className="form-group">
                <label>PASSWORD (SIMULATED)</label>
                <input
                  type="password"
                  name="password"
                  placeholder="Enter evaluation password"
                  value={formData.password}
                  onChange={handleChange}
                  required
                />
              </div>

              <button type="submit" disabled={loading}>
                {loading ? "EVALUATING RISK SIGNALS..." : "ANALYZE & REGISTER"}
                {!loading && <span>→</span>}
              </button>
            </form>

            {message && (
              <div
                className={`status-banner ${
                  analysis?.action === "BLOCK"
                    ? "status-block"
                    : analysis?.action === "CHALLENGE"
                    ? "status-challenge"
                    : analysis?.action === "REVIEW"
                    ? "status-review"
                    : "status-allow"
                }`}
              >
                {message}
              </div>
            )}

            {/* REAL-TIME RISK ANALYSIS BREAKDOWN */}
            {analysis && (
              <div className="analysis-card">
                <div className="analysis-header">
                  <div>
                    <span className="analysis-label">RISK EVALUATION RESULT</span>
                    <h3>Composite Threat: {analysis.risk_score} / 100</h3>
                  </div>
                  <div className="badges-row">
                    <span className={`level-badge level-${analysis.risk_level.toLowerCase()}`}>
                      {analysis.risk_level} RISK
                    </span>
                    <span className={`action-badge action-${(verified ? "ALLOW" : analysis.action).toLowerCase()}`}>
                      {verified ? "ALLOW (VERIFIED)" : analysis.action}
                    </span>
                  </div>
                </div>

                <div className="scores-trio">
                  <div className="score-box">
                    <span className="score-lbl">RULES (60%)</span>
                    <strong>{analysis.scores.rule_score}</strong>
                  </div>
                  <div className="score-box">
                    <span className="score-lbl">BEHAVIOR (25%)</span>
                    <strong>{analysis.scores.behavior_score}</strong>
                  </div>
                  <div className="score-box">
                    <span className="score-lbl">ML ANOMALY (15%)</span>
                    <strong>{analysis.scores.ml_score}</strong>
                  </div>
                </div>

                {analysis.signals.length > 0 ? (
                  <div className="signals-list">
                    <span className="signals-title">DETECTED RISK SIGNALS ({analysis.signals.length}):</span>
                    {analysis.signals.map((sig, idx) => (
                      <div key={idx} className="signal-item">
                        <div>
                          <strong>{sig.type}</strong>
                          <p>{sig.message}</p>
                        </div>
                        <span className="signal-pts">+{sig.points} pts</span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="clean-signal">✓ No suspicious telemetry or identity signals detected.</div>
                )}
              </div>
            )}

            {/* INTERACTIVE CHALLENGE VERIFICATION */}
            {analysis && analysis.action === "CHALLENGE" && !verified && (
              <div className="verify-panel">
                <h3>🔍 Stepped-Up Verification (CHALLENGE Tier)</h3>
                <p>
                  Our heuristics detected suspicious registration patterns. Confirm promotional
                  compliance to escalate this account to ALLOW.
                </p>

                <label className="verify-checkbox">
                  <input
                    type="checkbox"
                    checked={verifyChecked}
                    onChange={(e) => setVerifyChecked(e.target.checked)}
                  />
                  I confirm this is not a duplicate account created to reclaim promotional trial credits.
                </label>

                <button
                  type="button"
                  onClick={handleVerify}
                  disabled={!verifyChecked || verifying}
                >
                  {verifying ? "VERIFYING IDENTITY..." : "CONFIRM & UPGRADE TO ALLOW"}
                </button>
              </div>
            )}

            <div className="security-info">
              <span>🛡️</span>
              <div>
                <strong>Continuous Threat Intelligence</strong>
                <p>
                  Accounts sharing hardware fingerprints or subnet IPs are automatically correlated into
                  fraud rings visible in the Admin Console.
                </p>
              </div>
            </div>
          </section>
        </main>
      )}

      <footer>
        FRAUDGUARD <span>•</span> MULTI-ACCOUNT ABUSE DETECTION & RISK ANALYTICS <span>•</span> DECISION SUPPORT SYSTEM
      </footer>
    </div>
  );
}

export default App;
