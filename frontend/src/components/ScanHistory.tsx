import type { ScanSummary } from "../App";

interface Props {
  history: ScanSummary[];
  onSelect: (scan: ScanSummary) => void;
}

function ScanHistory({ history, onSelect }: Props) {
  return (
    <div className="scan-history">
      <h3>Recent Scans</h3>
      {history.length === 0 ? (
        <p className="hint">No scans yet.</p>
      ) : (
        <ul>
          {history.map((scan) => (
            <li key={scan.id} onClick={() => onSelect(scan)}>
              <div>
                <p className="target">{scan.target_url}</p>
                <p className="meta">{scan.status} • {new Date(scan.created_at).toLocaleString()}</p>
              </div>
              <span className="risk">{(scan.summary_risk || 0).toFixed(1)}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

export default ScanHistory;
