import type { Scan } from "../App";

interface Props {
  scan: Scan | null;
  apiBase: string;
  token: string;
}

const severityColor: Record<string, string> = {
  critical: "critical",
  high: "high",
  medium: "medium",
  low: "low",
  info: "info",
};

function ScanResults({ scan, apiBase, token }: Props) {
  if (!scan) {
    return (
      <div className="empty-state">
        <h3>No scan yet</h3>
        <p>Kick off a scan to see findings, risk scores, and exportable reports.</p>
      </div>
    );
  }

  const downloadReport = async (format: "json" | "pdf") => {
    const response = await fetch(`${apiBase}/scan/${scan.id}/report?format=${format}`, {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });
    if (!response.ok) {
      return;
    }
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `scan-${scan.id}.${format}`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="scan-results">
      <div className="scan-meta">
        <div>
          <p className="label">Target</p>
          <p className="value">{scan.target_url}</p>
        </div>
        <div>
          <p className="label">Status</p>
          <p className="value">{scan.status}</p>
        </div>
        <div>
          <p className="label">Risk Score</p>
          <p className="value">{(scan.summary_risk || 0).toFixed(1)}</p>
        </div>
      </div>

      <div className="actions">
        <button className="ghost" onClick={() => downloadReport("json")}>
          Export JSON
        </button>
        <button className="ghost" onClick={() => downloadReport("pdf")}>
          Export PDF
        </button>
      </div>

      <div className="findings">
        {scan.findings.length === 0 ? (
          <p className="hint">No findings yet. If scan is running, results will appear soon.</p>
        ) : (
          scan.findings.map((finding) => (
            <article key={finding.id} className="finding-card">
              <div className="finding-header">
                <div>
                  <h4>{finding.title}</h4>
                  <p className="category">{finding.category}</p>
                </div>
                <span className={`severity ${severityColor[finding.severity.toLowerCase()] || "info"}`}>
                  {finding.severity.toUpperCase()} {finding.cvss_score.toFixed(1)}
                </span>
              </div>
              <p className="evidence">{finding.evidence}</p>
              <p className="recommendation">{finding.recommendation}</p>
            </article>
          ))
        )}
      </div>
    </div>
  );
}

export default ScanResults;
