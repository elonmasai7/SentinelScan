import { useEffect, useMemo, useState } from "react";
import ScanForm from "./components/ScanForm";
import ScanResults from "./components/ScanResults";
import ScanHistory from "./components/ScanHistory";
import RiskHeatmap from "./components/RiskHeatmap";
import FindingsPanel from "./components/FindingsPanel";

export type Finding = {
  id: string;
  title: string;
  category: string;
  severity: string;
  cvss_score: number;
  confidence: string;
  plugin: string;
  cwe?: string | null;
  evidence: string;
  recommendation: string;
  remediation?: string | null;
};

export type Scan = {
  id: string;
  project_id: string;
  target_url: string;
  status: string;
  created_at: string;
  completed_at?: string | null;
  summary_risk?: number | null;
  findings: Finding[];
};

export type ScanSummary = Omit<Scan, "findings">;

export type Project = {
  id: string;
  name: string;
  workspace_id: string;
};

const API_BASE = import.meta.env.VITE_API_BASE || "http://localhost:8000/api";

const statusCopy: Record<string, string> = {
  queued: "Queued",
  running: "Running",
  completed: "Completed",
  failed: "Failed",
};

function App() {
  const [activeScan, setActiveScan] = useState<Scan | null>(null);
  const [activeFinding, setActiveFinding] = useState<Finding | null>(null);
  const [history, setHistory] = useState<ScanSummary[]>([]);
  const [projects, setProjects] = useState<Project[]>([]);
  const [selectedProject, setSelectedProject] = useState<string>("");
  const [token, setToken] = useState<string>(localStorage.getItem("auth_token") || "");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const authFetch = (url: string, options: RequestInit = {}) => {
    const headers = new Headers(options.headers || {});
    if (token) {
      headers.set("Authorization", `Bearer ${token}`);
    }
    return fetch(url, { ...options, headers });
  };

  const fetchHistory = async () => {
    if (!token) return;
    const response = await authFetch(`${API_BASE}/scans`);
    if (!response.ok) {
      return;
    }
    const data = await response.json();
    setHistory(data);
  };

  const fetchProjects = async () => {
    if (!token) return;
    const response = await authFetch(`${API_BASE}/org/projects`);
    if (!response.ok) {
      return;
    }
    const data = await response.json();
    if (data.length === 0) {
      await ensureDefaultProject();
      return;
    }
    setProjects(data);
    if (data.length > 0 && !selectedProject) {
      setSelectedProject(data[0].id);
    }
  };

  const ensureDefaultProject = async () => {
    if (!token) return;
    try {
      const wsResponse = await authFetch(`${API_BASE}/org/workspaces`);
      if (!wsResponse.ok) {
        return;
      }
      let workspaces = await wsResponse.json();
      if (!workspaces || workspaces.length === 0) {
        const createWs = await authFetch(
          `${API_BASE}/org/workspaces?name=${encodeURIComponent("Demo Workspace")}`,
          { method: "POST" },
        );
        if (!createWs.ok) {
          return;
        }
        workspaces = [await createWs.json()];
      }
      const workspaceId = workspaces[0]?.id;
      if (!workspaceId) return;
      const createProject = await authFetch(
        `${API_BASE}/org/projects?workspace_id=${encodeURIComponent(workspaceId)}&name=${encodeURIComponent(
          "Demo Project",
        )}`,
        { method: "POST" },
      );
      if (!createProject.ok) {
        return;
      }
      const project = await createProject.json();
      setProjects([project]);
      setSelectedProject(project.id);
    } catch {
      // leave as-is if provisioning fails
    }
  };

  useEffect(() => {
    if (token) {
      fetchHistory();
      fetchProjects();
    }
  }, [token]);

  const pollScan = async (scanId: string) => {
    let done = false;
    while (!done) {
      const response = await authFetch(`${API_BASE}/scan/${scanId}`);
      if (!response.ok) {
        throw new Error("Failed to fetch scan status");
      }
      const data = await response.json();
      setActiveScan(data);
      if (data.findings && data.findings.length > 0 && !activeFinding) {
        setActiveFinding(data.findings[0]);
      }
      if (data.status === "completed" || data.status === "failed") {
        done = true;
        await fetchHistory();
      } else {
        await new Promise((resolve) => setTimeout(resolve, 2000));
      }
    }
  };

  const startScan = async (targetUrl: string, bearerToken: string, demoMode: boolean) => {
    setError(null);
    setLoading(true);
    setActiveScan(null);
    try {
      if (!selectedProject) {
        throw new Error("Select a project first");
      }
      const response = await authFetch(`${API_BASE}/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target_url: targetUrl,
          bearer_token: bearerToken || null,
          demo_mode: demoMode,
          project_id: selectedProject,
        }),
      });
      if (!response.ok) {
        throw new Error("Failed to create scan");
      }
      const scan = await response.json();
      setActiveFinding(null);
      await pollScan(scan.id);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const handleAuth = async (mode: "login" | "register", email: string, password: string) => {
    setError(null);
    try {
      const response = await fetch(`${API_BASE}/auth/${mode}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password }),
      });
      if (!response.ok) {
        throw new Error("Authentication failed");
      }
      const data = await response.json();
      localStorage.setItem("auth_token", data.access_token);
      setToken(data.access_token);
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const summaryRisk = useMemo(() => {
    if (!activeScan?.summary_risk) return 0;
    return activeScan.summary_risk;
  }, [activeScan]);

  return (
    <div className="app">
      <header className="hero">
        <div>
          <p className="eyebrow">SentinelScan</p>
          <h1>REST API Vulnerability Scanner</h1>
          <p className="subtitle">
            Async OWASP Top 10 checks, CVSS-style scoring, and export-ready reports. Built for modern backend teams.
          </p>
        </div>
        <div className="hero-card">
          <div>
            <span>Active Scan</span>
            <strong>{activeScan ? statusCopy[activeScan.status] || activeScan.status : "Idle"}</strong>
          </div>
          <div>
            <span>Risk Score</span>
            <strong>{summaryRisk.toFixed(1)}</strong>
          </div>
        </div>
      </header>

      <main className="grid">
        <section className="panel">
          <ScanForm
            onSubmit={startScan}
            onAuth={handleAuth}
            loading={loading}
            token={token}
            projects={projects}
            selectedProject={selectedProject}
            onProjectChange={setSelectedProject}
          />
          {error && <p className="error">{error}</p>}
        </section>

        <section className="panel results">
          <div className="results-header">
            <div>
              <h3>Risk Overview</h3>
              <p className="hint">CVSS-style distribution across findings.</p>
            </div>
            <div className="actions">
              <ScanResults scan={activeScan} apiBase={API_BASE} token={token} compact />
            </div>
          </div>
          <RiskHeatmap scan={activeScan} />
          <div className="findings-layout">
            <div>
              <h3>Findings</h3>
              <FindingsPanel
                findings={activeScan?.findings || []}
                activeId={activeFinding?.id || null}
                onSelect={(finding) => setActiveFinding(finding)}
              />
            </div>
            <div className="remediation-card">
              <h3>AI Remediation</h3>
              {activeFinding ? (
                <>
                  <p className="title">{activeFinding.title}</p>
                  <p className="meta">
                    {activeFinding.category} • {activeFinding.cwe ? `CWE ${activeFinding.cwe}` : "No CWE mapped"}
                  </p>
                  <p className="evidence">{activeFinding.evidence}</p>
                  <p className="recommendation">{activeFinding.remediation || activeFinding.recommendation}</p>
                </>
              ) : (
                <p className="hint">Select a finding to view remediation guidance.</p>
              )}
            </div>
          </div>
        </section>

        <section className="panel history">
          <ScanHistory
            history={history}
            onSelect={async (scan) => {
              const response = await authFetch(`${API_BASE}/scan/${scan.id}`);
              if (!response.ok) {
                return;
              }
              const data = await response.json();
              setActiveScan(data);
              setActiveFinding(data.findings?.[0] || null);
            }}
          />
        </section>
      </main>
    </div>
  );
}

export default App;
