# Synthetic document templates

These reports contain invented company data for the KARMA demonstration. They contain
no macros, automatic callbacks, scripts, embedded files or executable payloads.
Their placeholder acknowledgement links are replaced in memory with per-session
links when the SSH/SFTP sensor prepares a copy. Templates are never overwritten by
sensor clients. The production runtime requires only the committed templates and pypdf.

Build-time sources are `tools/build_decoy_pdf.py` (ReportLab) and
`tools/build_decoy_workbook.mjs` (@oai/artifact-tool). After building the spreadsheet,
run `python -m tools.finalize_decoy_workbook` from the project root to add its plain
OOXML hyperlink. The spreadsheet renderer does not support HYPERLINK calculation;
the saved workbook therefore uses a native hyperlink relationship instead of a
formula. Financial calculations use ordinary SUM, subtraction and division.

The workbook uses a fiscal year ending March 2026; amounts are INR lakh. The
synthetic annual revenue is 580, operating profit 203 and operating margin 35%.
Previews and the builder's inspection output are local build artifacts, not runtime
data. Do not replace these templates with real confidential records.
