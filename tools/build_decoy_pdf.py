"""Build the static, synthetic report template; requires ReportLab at build time."""
from pathlib import Path
from reportlab.pdfgen import canvas
from reportlab.lib.colors import HexColor
from reportlab.lib.pagesizes import A4

root = Path(__file__).resolve().parents[1]
output = root / 'backend' / 'assets' / 'company_data_2026.pdf'
output.parent.mkdir(parents=True, exist_ok=True)
c = canvas.Canvas(str(output), pagesize=A4)
c.setTitle('Aegis Systems - Company Data 2026')
c.setAuthor('KARMA Lab - Synthetic Data')
c.setFillColor(HexColor('#183b56'))
c.rect(0, 746, A4[0], 96, fill=1, stroke=0)
c.setFillColor(HexColor('#ffffff'))
c.setFont('Helvetica-Bold', 21)
c.drawString(44, 796, 'AEGIS SYSTEMS')
c.setFont('Helvetica', 12)
c.drawString(44, 773, 'Company data register | 2026')
c.setFillColor(HexColor('#172033'))
c.setFont('Helvetica-Bold', 16)
c.drawString(44, 707, 'Operations review')
c.setFont('Helvetica', 10)
for y, line in zip([682,666,650], [
 'Prepared by: Corporate Operations | Review cycle: October 2026',
 'Business unit: Managed infrastructure services | Office: Bengaluru',
 'Synthetic company data for the KARMA security lab.'
]): c.drawString(44,y,line)
c.setFont('Helvetica-Bold',12)
c.drawString(44,611,'Account portfolio')
rows = [('Account','Service','Annual value (INR lakh)'),
 ('Cedar Manufacturing','Infrastructure support','168'),
 ('Maple Logistics','Platform operations','142'),
 ('Summit Retail','Cloud services','126'),
 ('Harbor Analytics','Application support','144')]
for i,row in enumerate(rows):
 y=582-i*34
 c.setFillColor(HexColor('#eaf0f6' if i%2==0 else '#ffffff'))
 c.rect(44,y-10,507,30,fill=1,stroke=0)
 c.setFillColor(HexColor('#172033'))
 c.setFont('Helvetica-Bold' if i==0 else 'Helvetica',10)
 for x,text in zip([52,219,386],row): c.drawString(x,y,text)
c.setFont('Helvetica-Bold',12)
c.drawString(44,376,'Document acknowledgement')
c.setFont('Helvetica',10)
for y,line in zip([352,335,318],[
 'Use the link below to visit the document register and confirm this lab interaction.',
 'The confirmation button sends an event to the KARMA dashboard.',
 'Opening this PDF alone sends no signal. No executable code or backdoor.'
]): c.drawString(44,y,line)
c.setFillColor(HexColor('#245bc2'))
c.drawString(44,281,'Open document acknowledgement page')
c.linkURL('https://karma.invalid/document/PLACEHOLDER',(44,277,300,293),relative=0)
c.setStrokeColor(HexColor('#cbd5e1'))
c.line(44,74,551,74)
c.setFillColor(HexColor('#64748b'))
c.setFont('Helvetica',9)
c.drawString(44,54,'AEGIS / OPS / 2026-104 | Security training fixture')
c.drawRightString(551,54,'1 / 1')
c.save()
