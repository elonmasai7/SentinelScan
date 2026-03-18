import { useState } from "react";
import type { Project } from "../App";

interface ScanFormProps {
  onSubmit: (targetUrl: string, bearerToken: string, demoMode: boolean) => void;
  onAuth: (mode: "login" | "register", email: string, password: string) => void;
  loading: boolean;
  token: string;
  projects: Project[];
  selectedProject: string;
  onProjectChange: (projectId: string) => void;
}

function ScanForm({
  onSubmit,
  onAuth,
  loading,
  token,
  projects,
  selectedProject,
  onProjectChange,
}: ScanFormProps) {
  const [targetUrl, setTargetUrl] = useState("https://api.example.com/users/1");
  const [bearerToken, setBearerToken] = useState("");
  const [demoMode, setDemoMode] = useState(true);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");

  return (
    <div className="scan-form">
      <h2>Workspace Access</h2>
      {!token ? (
        <div className="auth-box">
          <label>
            Email
            <input value={email} onChange={(event) => setEmail(event.target.value)} placeholder="you@company.com" />
          </label>
          <label>
            Password
            <input
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              type="password"
              placeholder="********"
            />
          </label>
          <div className="auth-actions">
            <button className="ghost" onClick={() => onAuth("login", email, password)}>
              Login
            </button>
            <button className="primary" onClick={() => onAuth("register", email, password)}>
              Create Account
            </button>
          </div>
        </div>
      ) : (
        <p className="hint">Authenticated. Select a project to run scans.</p>
      )}

      <h2>Scan Target</h2>
      <label>
        Project
        <select value={selectedProject} onChange={(event) => onProjectChange(event.target.value)}>
          {projects.length === 0 ? (
            <option value="">No projects yet</option>
          ) : (
            projects.map((project) => (
              <option key={project.id} value={project.id}>
                {project.name}
              </option>
            ))
          )}
        </select>
      </label>
      <label>
        API Endpoint URL
        <input
          value={targetUrl}
          onChange={(event) => setTargetUrl(event.target.value)}
          placeholder="https://api.example.com/users/1"
        />
      </label>
      <label>
        Bearer Token (optional)
        <input
          value={bearerToken}
          onChange={(event) => setBearerToken(event.target.value)}
          placeholder="eyJhbGciOi..."
        />
      </label>
      <label className="toggle">
        <input type="checkbox" checked={demoMode} onChange={(event) => setDemoMode(event.target.checked)} />
        Demo mode (uses vulnerable local endpoint)
      </label>
      <button
        disabled={loading || !token || !selectedProject}
        onClick={() => onSubmit(targetUrl, bearerToken, demoMode)}
        className="primary"
      >
        {loading ? "Scanning..." : "Run Scan"}
      </button>
      <p className="hint">
        Demo mode will scan <code>http://localhost:8000/demo/users/1</code> so you can show results instantly.
      </p>
    </div>
  );
}

export default ScanForm;
