"""Harmless per-session document links. Nothing runs when a file is opened."""
import hashlib
import io
import ipaddress
import secrets
import time
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import urlsplit

from pypdf import PdfWriter
from pypdf.generic import NameObject, TextStringObject
from backend import config, database as db

ASSETS = Path(__file__).parent / 'assets'
# Templates that get a per-session acknowledgement link; every other asset is served as-is.
TEMPLATES = ('company_data_2026.pdf', 'company_financials_25-26.xlsx')
MAX_ASSET_BYTES = 50 * 1024 * 1024


def asset_files():
    """Decoy files offered over SSH/SFTP/FTP: whatever is in backend/assets right now.
    Drop a file in to offer it, delete it to withdraw it; new sessions see the change."""
    return tuple(sorted(p.name for p in ASSETS.iterdir()
                        if p.is_file() and not p.name.startswith('.') and p.name != 'README.md'
                        and p.stat().st_size <= MAX_ASSET_BYTES))
PLACEHOLDER = 'https://karma.invalid/document/PLACEHOLDER'
TTL = 7 * 86400
SHEET_NS = 'http://schemas.openxmlformats.org/spreadsheetml/2006/main'
REL_NS = 'http://schemas.openxmlformats.org/package/2006/relationships'
DOC_REL_NS = 'http://schemas.openxmlformats.org/officeDocument/2006/relationships'


def callback_base(local_address):
    value = config.CALLBACK_BASE_URL
    if not value:
        address = ipaddress.ip_address(local_address)
        host = f'[{address}]' if address.version == 6 else str(address)
        value = f'http://{host}:{config.PORT_WEB_HONEYPOT}'
    parsed = urlsplit(value)
    # Accessing port validates malformed/out-of-range explicit ports.
    parsed.port
    if (parsed.scheme not in ('http', 'https') or not parsed.hostname or parsed.username
            or parsed.password or parsed.query or parsed.fragment or parsed.path not in ('', '/')
            or any(ord(c) < 33 for c in value)):
        raise ValueError('KARMA_CALLBACK_BASE_URL must be an HTTP(S) origin without credentials')
    return value.rstrip('/')


def workbook_link(content, url):
    """Add a plain hyperlink to the authored template; no macro/external data source."""
    sheet_path = 'xl/worksheets/sheet1.xml'
    rel_path = 'xl/worksheets/_rels/sheet1.xml.rels'
    with zipfile.ZipFile(io.BytesIO(content)) as src:
        sheet = ET.fromstring(src.read(sheet_path))
        links = sheet.find(f'{{{SHEET_NS}}}hyperlinks')
        if links is None:
            links = ET.Element(f'{{{SHEET_NS}}}hyperlinks')
            # OOXML hyperlinks precede print/page layout nodes.
            insert_before = {'printOptions', 'pageMargins', 'pageSetup', 'headerFooter', 'drawing', 'extLst'}
            index = next((i for i, child in enumerate(sheet) if child.tag.split('}')[-1] in insert_before), len(sheet))
            sheet.insert(index, links)
        for link in list(links):
            if link.get('ref') == 'A15':
                links.remove(link)
        rid = 'rIdKarmaAcknowledgement'
        ET.SubElement(links, f'{{{SHEET_NS}}}hyperlink', {'ref':'A15', f'{{{DOC_REL_NS}}}id':rid})
        rels = ET.fromstring(src.read(rel_path)) if rel_path in src.namelist() else ET.Element(f'{{{REL_NS}}}Relationships')
        for rel in list(rels):
            if rel.get('Id') == rid:
                rels.remove(rel)
        ET.SubElement(rels, f'{{{REL_NS}}}Relationship', {'Id':rid, 'Type':DOC_REL_NS+'/hyperlink', 'Target':url, 'TargetMode':'External'})
        output = io.BytesIO()
        with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED) as dest:
            for entry in src.infolist():
                if entry.filename not in (sheet_path, rel_path):
                    dest.writestr(entry, src.read(entry.filename))
            dest.writestr(sheet_path, ET.tostring(sheet, encoding='utf-8', xml_declaration=True))
            dest.writestr(rel_path, ET.tostring(rels, encoding='utf-8', xml_declaration=True))
        return output.getvalue()


def personalize(filename, url):
    if filename not in asset_files():
        raise ValueError('Unknown decoy document')
    path = ASSETS / filename
    if filename not in TEMPLATES:
        return path.read_bytes()
    if filename.endswith('.xlsx'):
        return workbook_link(path.read_bytes(), url)
    writer = PdfWriter(clone_from=str(path))
    for page in writer.pages:
        for annotation in page.get('/Annots', []):
            action = annotation.get_object().get('/A')
            if action and action.get('/URI') == PLACEHOLDER:
                action[NameObject('/URI')] = TextStringObject(url)
    result = io.BytesIO()
    writer.write(result)
    return result.getvalue()


def issue_document(filename, source_ip, session_id, base):
    token = secrets.token_urlsafe(32)
    content = personalize(filename, f'{base}/documents/{token}')
    conn = db.get_db()
    try:
        now = int(time.time())
        conn.execute('DELETE FROM document_tokens WHERE expires_at < ?', (now,))
        conn.execute('INSERT INTO document_tokens VALUES (?, ?, ?, ?, ?, ?)',
                     (hashlib.sha256(token.encode()).hexdigest(), filename, source_ip, session_id, now, now+TTL))
        conn.execute('DELETE FROM document_tokens WHERE token_hash IN (SELECT token_hash FROM document_tokens ORDER BY created_at DESC, rowid DESC LIMIT -1 OFFSET 10000)')
        conn.commit()
    finally:
        conn.close()
    return content


def lookup_document(token):
    if len(token) != 43 or any(c not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_' for c in token):
        return None
    conn = db.get_db()
    try:
        row = conn.execute('SELECT filename, source_ip, session_id FROM document_tokens WHERE token_hash=? AND expires_at>=?',
                           (hashlib.sha256(token.encode()).hexdigest(), int(time.time()))).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def record_document_event(filename, source_ip, session_id, client_ip, confirmed=False, broadcast=None, port=None):
    import json
    event_id = db.log_attack_event(client_ip, config.PORT_WEB_HONEYPOT if confirmed else (port or config.PORT_SSH_HONEYPOT),
        'DOCUMENT_DECOY', 'Document interaction confirmed' if confirmed else 'Decoy file read started',
        json.dumps({'file':filename, 'original_source_ip':source_ip, 'session':session_id,
                    'observation':'Acknowledgement button submitted' if confirmed else 'First file bytes requested; complete download not established'}),
        '', '', '', 40 if confirmed else 25, 'MEDIUM' if confirmed else 'LOW')
    if broadcast:
        broadcast({'id':event_id, 'quarantined':False})
    return event_id
