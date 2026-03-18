import type { Scan } from "../App";

interface Props {
  scan: Scan | null;
  apiBase: string;
  token: string;
  compact?: boolean;
}

function ScanResults({ scan, apiBase, token, compact }: Props) {
  if (!scan) {
    return compact ? <span className="hint">No scan</span> : (
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
    <div className={compact ? "export-inline" : "scan-results"}>
      {!compact && (
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
      )}

      <div className="actions">
        <button className="ghost" onClick={() => downloadReport("json")}>
          Export JSON
        </button>
        <button className="ghost" onClick={() => downloadReport("pdf")}>
          Export PDF
        </button>
      </div>
    </div>
  );
}

export default ScanResults;
