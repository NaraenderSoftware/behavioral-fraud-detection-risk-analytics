import { useEffect, useState } from "react";
import "./Dashboard.css";

const API_BASE = import.meta.env.VITE_API_URL || "http://127.0.0.1:5000";

function Dashboard() {
  const [dashboard, setDashboard] = useState(null);
  const [users, setUsers] = useState([]);
  const [clusters, setClusters] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [searchQuery, setSearchQuery] = useState("");
  const [riskFilter, setRiskFilter] = useState("ALL");
  const [selectedUserDetail, setSelectedUserDetail] = useState(null);

  const loadDashboard = async () => {
    try {
      const [dashboardResponse, usersResponse, clustersResponse] =
        await Promise.all([
          fetch(API_BASE + "/api/dashboard"),
          fetch(API_BASE + "/api/users"),
          fetch(API_BASE + "/api/clusters"),
        ]);

      if (
        !dashboardResponse.ok ||
        !usersResponse.ok ||
        !clustersResponse.ok
      ) {
        throw new Error("Failed to load dashboard data");
      }

      const dashboardData = await dashboardResponse.json();
      const usersData = await usersResponse.json();
      const clustersData = await clustersResponse.json();

      setDashboard(dashboardData);
      setUsers(usersData);
      setClusters(clustersData);
      setError("");
    } catch (err) {
      console.error(err);
      setError("Cannot connect to FraudGuard backend.");
    } finally {
      setLoading(false);
    }
  };

  const resetDemo = async () => {
    if (!window.confirm("Reset all demo data? This will restore clean baseline demonstration accounts.")) return;
    try {
      await fetch(API_BASE + "/api/reset-demo", { method: "POST" });
      await new Promise((resolve) => setTimeout(resolve, 500));
      await loadDashboard();
    } catch (err) {
      console.error(err);
      setError("Failed to reset demo data.");
    }
  };

  const clusterAction = async (clusterId, status) => {
    try {
      await fetch(`${API_BASE}/api/clusters/${clusterId}/action`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status }),
      });
      await loadDashboard();
    } catch (err) {
      console.error(err);
      setError("Failed to update cluster.");
    }
  };

  const openUserDetail = async (userId) => {
    try {
      const res = await fetch(`${API_BASE}/api/users/${userId}`);
      if (res.ok) {
        const data = await res.json();
        setSelectedUserDetail(data);
      }
    } catch (err) {
      console.error("Failed to load user details", err);
    }
  };

  const closeUserDetail = () => {
    setSelectedUserDetail(null);
  };

  useEffect(() => {
    let isMounted = true;
    const fetchInitial = async () => {
      try {
        const [dashboardResponse, usersResponse, clustersResponse] =
          await Promise.all([
            fetch(API_BASE + "/api/dashboard"),
            fetch(API_BASE + "/api/users"),
            fetch(API_BASE + "/api/clusters"),
          ]);
        if (
          !dashboardResponse.ok ||
          !usersResponse.ok ||
          !clustersResponse.ok
        ) {
          throw new Error("Failed to load dashboard data");
        }
        const dashboardData = await dashboardResponse.json();
        const usersData = await usersResponse.json();
        const clustersData = await clustersResponse.json();
        if (isMounted) {
          setDashboard(dashboardData);
          setUsers(usersData);
          setClusters(clustersData);
          setError("");
          setLoading(false);
        }
      } catch (err) {
        console.error(err);
        if (isMounted) {
          setError("Cannot connect to FraudGuard backend.");
          setLoading(false);
        }
      }
    };
    fetchInitial();
    const interval = setInterval(loadDashboard, 5000);
    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, []);

  const filteredUsers = users.filter((u) => {
    const q = searchQuery.toLowerCase();
    const matchesSearch =
      u.name.toLowerCase().includes(q) ||
      u.email.toLowerCase().includes(q) ||
      (u.ip_address && u.ip_address.toLowerCase().includes(q));

    if (!matchesSearch) return false;
    if (riskFilter === "ALL") return true;
    return u.risk_level === riskFilter;
  });

  if (loading && !dashboard) {
    return (
      <div className="dashboard-page">
        <div className="dashboard-loading">
          Loading FraudGuard Intelligence...
        </div>
      </div>
    );
  }

  if (error && !dashboard) {
    return (
      <div className="dashboard-page">
        <div className="dashboard-error">
          {error}
        </div>
      </div>
    );
  }

  return (
    <div className="dashboard-page">
      {/* HEADER */}
      <header className="dashboard-navbar">
        <div className="dashboard-logo">
          <span className="dashboard-logo-icon">F</span>
          FRAUD<span>GUARD</span>
        </div>

        <div className="dashboard-status">
          <span className="dashboard-status-dot"></span>
          LIVE PROTECTION ACTIVE
        </div>
      </header>

      {/* MAIN CONTAINER */}
      <main className="dashboard-container">
        <div className="dashboard-heading">
          <div>
            <div className="dashboard-label">ADMINISTRATOR CONSOLE</div>
            <h1>Fraud Intelligence</h1>
            <p>
              Monitor multi-account abuse, risk signals, and identity reuse in real time.
            </p>
          </div>

          <div style={{ display: "flex", gap: "12px" }}>
            <button className="refresh-button" onClick={loadDashboard}>
              ↻ REFRESH
            </button>
            <button className="refresh-button" onClick={resetDemo}>
              ⟲ RESET DEMO
            </button>
          </div>
        </div>

        {error && <div className="dashboard-warning">⚠ {error}</div>}

        {/* STAT CARDS */}
        {dashboard && (
          <section className="stats-grid">
            <div className="stat-card">
              <div className="stat-title">TOTAL USERS</div>
              <div className="stat-value">{dashboard.total_users}</div>
              <div className="stat-description">Accounts analyzed</div>
            </div>

            <div className="stat-card">
              <div className="stat-title">AVERAGE RISK</div>
              <div className="stat-value">{dashboard.average_risk}</div>
              <div className="stat-description">Threat composite (0-100)</div>
            </div>

            <div className="stat-card">
              <div className="stat-title">CHALLENGED</div>
              <div className="stat-value" style={{ color: "var(--color-challenge, #ffd166)" }}>
                {dashboard.challenge}
              </div>
              <div className="stat-description">Identity verification required</div>
            </div>

            <div className="stat-card">
              <div className="stat-title">BLOCKED</div>
              <div className="stat-value" style={{ color: "var(--color-block, #ff4d6d)" }}>
                {dashboard.blocked}
              </div>
              <div className="stat-description">Prevented malicious signups</div>
            </div>

            <div className="stat-card">
              <div className="stat-title">FRAUD CLUSTERS</div>
              <div className="stat-value" style={{ color: "#ff9b70" }}>
                {dashboard.active_clusters}
              </div>
              <div className="stat-description">Likely-linked account rings</div>
            </div>
          </section>
        )}

        {/* RISK DISTRIBUTION */}
        {dashboard && (
          <section className="dashboard-section">
            <div className="section-header">
              <div>
                <div className="section-label">RISK DISTRIBUTION</div>
                <h2>Current Threat Profile</h2>
              </div>
            </div>

            <div className="risk-grid">
              {dashboard.risk_distribution.map((item) => (
                <div
                  className={`risk-card risk-${item.risk_level.toLowerCase()}`}
                  key={item.risk_level}
                >
                  <div className="risk-card-top">
                    <span className="risk-name">{item.risk_level}</span>
                    <span className="risk-count">{item.count}</span>
                  </div>

                  <div className="risk-bar">
                    <div
                      className="risk-bar-fill"
                      style={{
                        width: `${
                          dashboard.total_users > 0
                            ? Math.min(
                                100,
                                (item.count / dashboard.total_users) * 100
                              )
                            : 0
                        }%`,
                      }}
                    />
                  </div>

                  <div className="risk-percentage">
                    {dashboard.total_users > 0
                      ? ((item.count / dashboard.total_users) * 100).toFixed(1)
                      : 0}
                    % of accounts
                  </div>
                </div>
              ))}
            </div>
          </section>
        )}

        {/* SCORE TIMELINE */}
        {users.length > 0 && (
          <section className="dashboard-section">
            <div className="section-header">
              <div>
                <div className="section-label">SCORE TIMELINE</div>
                <h2>Chronological Risk Scores</h2>
              </div>
              <div style={{ fontSize: "11px", color: "#8b949e" }}>
                Click bar to inspect account details
              </div>
            </div>

            <div
              style={{
                display: "flex",
                alignItems: "flex-end",
                gap: "12px",
                height: "170px",
                padding: "20px 24px",
              }}
            >
              {users.slice(0, 15).reverse().map((user) => (
                <div
                  key={user.id}
                  onClick={() => openUserDetail(user.id)}
                  style={{
                    display: "flex",
                    flexDirection: "column",
                    alignItems: "center",
                    flex: 1,
                    cursor: "pointer",
                  }}
                  title={`${user.name} - Score: ${user.risk_score} (${user.action})`}
                >
                  <div
                    style={{
                      width: "100%",
                      maxWidth: "36px",
                      height: `${Math.max(6, (user.risk_score / 100) * 130)}px`,
                      background:
                        user.risk_score >= 85
                          ? "#ff4d6d"
                          : user.risk_score >= 70
                          ? "#ff9b70"
                          : user.risk_score >= 50
                          ? "#ffd166"
                          : "#00f5a0",
                      borderRadius: "3px 3px 0 0",
                      transition: "opacity 0.2s",
                    }}
                  />
                  <div style={{ fontSize: "10px", marginTop: "6px", opacity: 0.8, fontFamily: "monospace" }}>
                    {user.risk_score}
                  </div>
                  <div style={{ fontSize: "9px", opacity: 0.5 }}>#{user.id}</div>
                </div>
              ))}
            </div>
          </section>
        )}

        {/* FRAUD CLUSTERS */}
        <section className="dashboard-section">
          <div className="section-header">
            <div>
              <div className="section-label">MULTI-ACCOUNT ABUSE</div>
              <h2>Likely-Linked Account Clusters</h2>
            </div>
          </div>

          <div className="users-table-wrapper">
            {clusters.length === 0 ? (
              <div className="empty-users">
                No linked-account clusters detected yet.
              </div>
            ) : (
              <table className="users-table">
                <thead>
                  <tr>
                    <th>CLUSTER TYPE</th>
                    <th>MEMBERS</th>
                    <th>SCORE</th>
                    <th>REASON</th>
                    <th>LINKED ACCOUNTS</th>
                    <th>STATUS</th>
                    <th>ACTIONS</th>
                  </tr>
                </thead>
                <tbody>
                  {clusters.map((cluster) => (
                    <tr key={cluster.id}>
                      <td>
                        <span className="table-risk-score" style={{ fontSize: "12px", color: "#00f5a0" }}>
                          {cluster.cluster_type}
                        </span>
                      </td>
                      <td>
                        <strong>{cluster.member_count}</strong> accounts
                      </td>
                      <td>
                        <span style={{ color: "#ff9b70", fontWeight: "bold" }}>
                          {cluster.cluster_score}
                        </span>
                      </td>
                      <td>{cluster.reason}</td>
                      <td>
                        {cluster.members
                          .map((m) => `${m.name} (${m.action})`)
                          .join(", ")}
                      </td>
                      <td>
                        <span
                          className={`action-badge action-${(
                            cluster.status || "active"
                          ).toLowerCase()}`}
                        >
                          {cluster.status || "ACTIVE"}
                        </span>
                      </td>
                      <td>
                        <div style={{ display: "flex", gap: "6px" }}>
                          <button
                            className="refresh-button"
                            style={{ padding: "5px 9px", fontSize: "9px" }}
                            onClick={() => clusterAction(cluster.id, "FLAGGED")}
                          >
                            FLAG
                          </button>
                          <button
                            className="refresh-button"
                            style={{ padding: "5px 9px", fontSize: "9px" }}
                            onClick={() => clusterAction(cluster.id, "RESTRICTED")}
                          >
                            RESTRICT
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </section>

        {/* USER TABLE WITH SEARCH & FILTER */}
        <section className="dashboard-section">
          <div className="section-header">
            <div>
              <div className="section-label">ACCOUNT ACTIVITY</div>
              <h2>Recent Signups Intelligence</h2>
            </div>
            <div className="live-indicator">
              <span></span>
              LIVE FEED
            </div>
          </div>

          {/* Search & Filter Toolbar */}
          <div className="table-toolbar">
            <div className="search-box">
              <input
                type="text"
                placeholder="Search by name, email, or IP..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
              />
            </div>

            <div className="filter-pills">
              {["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"].map((lvl) => (
                <button
                  key={lvl}
                  className={`pill-btn ${riskFilter === lvl ? "active" : ""}`}
                  onClick={() => setRiskFilter(lvl)}
                >
                  {lvl}
                </button>
              ))}
            </div>
          </div>

          <div className="users-table-wrapper">
            <table className="users-table">
              <thead>
                <tr>
                  <th>USER</th>
                  <th>EMAIL</th>
                  <th>RISK</th>
                  <th>LEVEL</th>
                  <th>ACTION</th>
                  <th>IP ADDRESS</th>
                  <th>ACTIONS</th>
                </tr>
              </thead>
              <tbody>
                {filteredUsers.map((user) => (
                  <tr key={user.id} onClick={() => openUserDetail(user.id)}>
                    <td>
                      <div className="user-name">{user.name}</div>
                      <div className="user-id">ID #{user.id}</div>
                    </td>
                    <td>{user.email}</td>
                    <td>
                      <span className="table-risk-score">{user.risk_score}</span>
                    </td>
                    <td>
                      <span
                        className={`level-badge level-${user.risk_level.toLowerCase()}`}
                      >
                        {user.risk_level}
                      </span>
                    </td>
                    <td>
                      <span
                        className={`action-badge action-${user.action.toLowerCase()}`}
                      >
                        {user.action}
                      </span>
                    </td>
                    <td className="ip-address">{user.ip_address}</td>
                    <td>
                      <button
                        className="refresh-button"
                        style={{ padding: "4px 8px", fontSize: "9px" }}
                        onClick={(e) => {
                          e.stopPropagation();
                          openUserDetail(user.id);
                        }}
                      >
                        INSPECT
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>

            {filteredUsers.length === 0 && (
              <div className="empty-users">
                No accounts match the active filter criteria.
              </div>
            )}
          </div>
        </section>

        {/* FOOTER */}
        <div className="dashboard-footer">
          <div>
            FRAUDGUARD <span>•</span> MULTI-ACCOUNT ABUSE PREVENTION
          </div>
          <div>DATA REFRESH: 5 SECONDS</div>
        </div>
      </main>

      {/* USER DETAIL INSPECTION DRAWER */}
      {selectedUserDetail && (
        <>
          <div className="drawer-backdrop" onClick={closeUserDetail}></div>
          <aside className="drawer">
            <div className="drawer-header">
              <div>
                <h3>{selectedUserDetail.user.name}</h3>
                <p>
                  USER #{selectedUserDetail.user.id} • {selectedUserDetail.user.email}
                </p>
              </div>
              <button className="close-btn" onClick={closeUserDetail}>
                ✕
              </button>
            </div>

            <div className="drawer-content">
              {/* Score Meter */}
              <div className="drawer-section">
                <div className="drawer-section-title">RISK ASSESSMENT</div>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "8px" }}>
                  <span style={{ fontSize: "13px" }}>Composite Threat Score</span>
                  <span style={{ fontSize: "24px", fontWeight: "bold", fontFamily: "monospace" }}>
                    {selectedUserDetail.user.risk_score} / 100
                  </span>
                </div>
                <div className="risk-bar" style={{ height: "8px" }}>
                  <div
                    className="risk-bar-fill"
                    style={{
                      width: `${selectedUserDetail.user.risk_score}%`,
                      background:
                        selectedUserDetail.user.risk_score >= 85
                          ? "#ff4d6d"
                          : selectedUserDetail.user.risk_score >= 70
                          ? "#ff9b70"
                          : selectedUserDetail.user.risk_score >= 50
                          ? "#ffd166"
                          : "#00f5a0",
                    }}
                  />
                </div>
                <div style={{ display: "flex", gap: "10px", marginTop: "10px" }}>
                  <span className={`level-badge level-${selectedUserDetail.user.risk_level.toLowerCase()}`}>
                    {selectedUserDetail.user.risk_level}
                  </span>
                  <span className={`action-badge action-${selectedUserDetail.user.action.toLowerCase()}`}>
                    {selectedUserDetail.user.action}
                  </span>
                </div>
              </div>

              {/* Assessment Breakdown */}
              {selectedUserDetail.assessments && selectedUserDetail.assessments[0] && (
                <div className="drawer-section">
                  <div className="drawer-section-title">WEIGHTED SCORE BREAKDOWN</div>
                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: "10px", textAlign: "center" }}>
                    <div style={{ background: "#080c10", padding: "10px", border: "1px solid #202731" }}>
                      <div style={{ fontSize: "9px", color: "#8b949e" }}>RULE SCORE (60%)</div>
                      <div style={{ fontSize: "18px", fontWeight: "bold" }}>
                        {selectedUserDetail.assessments[0].rule_score}
                      </div>
                    </div>
                    <div style={{ background: "#080c10", padding: "10px", border: "1px solid #202731" }}>
                      <div style={{ fontSize: "9px", color: "#8b949e" }}>BEHAVIOR (25%)</div>
                      <div style={{ fontSize: "18px", fontWeight: "bold" }}>
                        {selectedUserDetail.assessments[0].behavior_score}
                      </div>
                    </div>
                    <div style={{ background: "#080c10", padding: "10px", border: "1px solid #202731" }}>
                      <div style={{ fontSize: "9px", color: "#8b949e" }}>ML ANOMALY (15%)</div>
                      <div style={{ fontSize: "18px", fontWeight: "bold" }}>
                        {selectedUserDetail.assessments[0].ml_score}
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {/* Signals */}
              <div className="drawer-section">
                <div className="drawer-section-title">DETECTED SIGNALS</div>
                {selectedUserDetail.signals.length === 0 ? (
                  <div style={{ fontSize: "12px", color: "#00f5a0", padding: "12px", background: "#080c10" }}>
                    ✓ Clean profile. No suspicious signals recorded.
                  </div>
                ) : (
                  selectedUserDetail.signals.map((s, idx) => (
                    <div
                      key={idx}
                      style={{
                        padding: "10px 14px",
                        marginBottom: "8px",
                        background: "#080c10",
                        border: "1px solid #1f2733",
                        display: "flex",
                        justifyContent: "space-between",
                        alignItems: "flex-start",
                      }}
                    >
                      <div>
                        <div style={{ fontSize: "11px", fontWeight: "bold", color: "#fff" }}>
                          {s.signal_type}
                        </div>
                        <div style={{ fontSize: "11px", color: "#8b949e", marginTop: "2px" }}>
                          {s.message}
                        </div>
                      </div>
                      <div style={{ color: "#ff9b70", fontWeight: "bold", fontSize: "12px", fontFamily: "monospace" }}>
                        +{s.points} pts
                      </div>
                    </div>
                  ))
                )}
              </div>

              {/* Hardware and Network Context */}
              <div className="drawer-section">
                <div className="drawer-section-title">DEVICE & ENVIRONMENT CONTEXT</div>
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "8px", fontSize: "11px" }}>
                  <div style={{ background: "#080c10", padding: "8px 12px", border: "1px solid #1b222c" }}>
                    <div style={{ color: "#68727e", fontSize: "9px" }}>IP ADDRESS</div>
                    <div style={{ fontFamily: "monospace" }}>{selectedUserDetail.user.ip_address || "None"}</div>
                  </div>
                  <div style={{ background: "#080c10", padding: "8px 12px", border: "1px solid #1b222c" }}>
                    <div style={{ color: "#68727e", fontSize: "9px" }}>TIMEZONE</div>
                    <div>{selectedUserDetail.user.timezone || "UTC"}</div>
                  </div>
                  <div style={{ background: "#080c10", padding: "8px 12px", border: "1px solid #1b222c" }}>
                    <div style={{ color: "#68727e", fontSize: "9px" }}>RESOLUTION</div>
                    <div>{selectedUserDetail.user.screen_width}x{selectedUserDetail.user.screen_height}</div>
                  </div>
                  <div style={{ background: "#080c10", padding: "8px 12px", border: "1px solid #1b222c" }}>
                    <div style={{ color: "#68727e", fontSize: "9px" }}>CREATED AT</div>
                    <div>{selectedUserDetail.user.created_at ? selectedUserDetail.user.created_at.slice(0, 19).replace("T", " ") : "--"}</div>
                  </div>
                  <div style={{ background: "#080c10", padding: "8px 12px", border: "1px solid #1b222c", gridColumn: "span 2" }}>
                    <div style={{ color: "#68727e", fontSize: "9px" }}>DEVICE FINGERPRINT</div>
                    <div style={{ fontFamily: "monospace", wordBreak: "break-all", fontSize: "10px" }}>
                      {selectedUserDetail.user.device_fingerprint || "None"}
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </aside>
        </>
      )}
    </div>
  );
}

export default Dashboard;
