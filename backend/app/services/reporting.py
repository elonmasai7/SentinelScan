from io import BytesIO
from typing import List

from fpdf import FPDF

from app.db import models


class ReportPDF(FPDF):
    def header(self) -> None:
        self.set_font("Helvetica", "B", 16)
        self.cell(0, 10, "SentinelScan Report", ln=True)
        self.ln(2)


def build_pdf(scan: models.Scan, findings: List[models.Finding]) -> bytes:
    pdf = ReportPDF()
    pdf.add_page()
    pdf.set_font("Helvetica", size=12)

    pdf.cell(0, 8, f"Target: {scan.target_url}", ln=True)
    pdf.cell(0, 8, f"Status: {scan.status}", ln=True)
    pdf.cell(0, 8, f"Summary Risk: {scan.summary_risk or 0:.1f}", ln=True)
    pdf.ln(4)

    for finding in findings:
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 7, f"{finding.title} ({finding.severity.upper()} {finding.cvss_score:.1f})", ln=True)
        pdf.set_font("Helvetica", size=11)
        pdf.multi_cell(0, 6, f"Category: {finding.category}")
        pdf.multi_cell(0, 6, f"Evidence: {finding.evidence}")
        pdf.multi_cell(0, 6, f"Recommendation: {finding.recommendation}")
        if finding.remediation:
            pdf.multi_cell(0, 6, f"AI Remediation: {finding.remediation}")
        pdf.ln(2)

    buffer = BytesIO()
    pdf.output(buffer)
    return buffer.getvalue()
