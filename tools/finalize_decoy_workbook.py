"""Add the ordinary OOXML hyperlink unsupported by the build-time sheet renderer.

Run from the repository root with: python -m tools.finalize_decoy_workbook
"""
from backend.documents import ASSETS, PLACEHOLDER, workbook_link

if __name__ == '__main__':
    path = ASSETS / 'company_financials_25-26.xlsx'
    path.write_bytes(workbook_link(path.read_bytes(), PLACEHOLDER))
