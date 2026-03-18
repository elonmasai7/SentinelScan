import type { Scan } from "../App";

interface Props {
  scan: Scan | null;
}

const bands = [
  { label: "Critical", color: "var(--critical)", min: 9 },
  { label: "High", color: "var(--high)", min: 7 },
  { label: "Medium", color: "var(--medium)", min: 4 },
  { label: "Low", color: "var(--low)", min: 1 },
  { label: "Info", color: "var(--info)", min: 0 },
];

function RiskHeatmap({ scan }: Props) {
  if (!scan) {
    return (
      <div className="heatmap empty">
        <p>No scan data yet.</p>
      </div>
    );
  }

  const totals = bands.map((band) => ({
    ...band,
    count: scan.findings.filter((finding) => finding.cvss_score >= band.min).length,
  }));

  return (
    <div className="heatmap">
      {totals.map((band) => (
        <div key={band.label} className="heatmap-row">
          <span className="heatmap-label">{band.label}</span>
          <div className="heatmap-bar">
            <span style={{ width: `${Math.min(100, band.count * 18)}%`, background: band.color }} />
          </div>
          <span className="heatmap-count">{band.count}</span>
        </div>
      ))}
    </div>
  );
}

export default RiskHeatmap;
