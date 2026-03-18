import type { Finding } from "../App";

interface Props {
  findings: Finding[];
  onSelect: (finding: Finding) => void;
  activeId: string | null;
}

const severityOrder = ["critical", "high", "medium", "low", "info"];

function FindingsPanel({ findings, onSelect, activeId }: Props) {
  const sorted = [...findings].sort(
    (a, b) => severityOrder.indexOf(a.severity.toLowerCase()) - severityOrder.indexOf(b.severity.toLowerCase())
  );

  if (sorted.length === 0) {
    return <p className="hint">No findings yet. If scan is running, results will appear soon.</p>;
  }

  return (
    <div className="finding-list">
      {sorted.map((finding) => (
        <button
          key={finding.id}
          onClick={() => onSelect(finding)}
          className={finding.id === activeId ? "finding-pill active" : "finding-pill"}
        >
          <span className={`severity ${finding.severity.toLowerCase()}`}>{finding.severity.toUpperCase()}</span>
          <div>
            <p className="title">{finding.title}</p>
            <p className="meta">{finding.category}</p>
          </div>
          <span className="score">{finding.cvss_score.toFixed(1)}</span>
        </button>
      ))}
    </div>
  );
}

export default FindingsPanel;
