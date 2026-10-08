"""Bounded in-memory shell and read-only SFTP. Never executes host commands."""
import fnmatch
import os
import posixpath
import shlex
import stat
import time
import uuid

import paramiko
from backend import documents, database as db


class VirtualShell:
    def __init__(self, client_ip, local_address, broadcast=None):
        self.ip, self.broadcast = client_ip, broadcast
        self.session = uuid.uuid4().hex
        self.base = documents.callback_base(local_address)
        self.cwd = '/root'
        self.document_port = 2222
        self.dirs = {'/', '/root', '/etc', '/home', '/home/admin', '/tmp', '/var', '/var/log', '/srv', '/srv/company'}
        self.files = {
            '/etc/passwd': b'root:x:0:0:root:/root:/bin/bash\nadmin:x:1000:1000:Operations:/home/admin:/bin/bash\n',
            '/etc/hostname': b'aegis-gateway\n',
            '/etc/issue': b'Ubuntu 22.04 LTS\n',
            '/var/log/application.log': b'2026-10-01T09:00:00Z INFO company archive sync complete\n',
            '/root/README.txt': b'Corporate records are in /root and /srv/company.\nUse SFTP to download reports.\nSecurity lab: all records are synthetic.\n',
            '/srv/company/contacts.csv': b'account,contact\nCedar Manufacturing,operations@cedar.example\nMaple Logistics,finance@maple.example\n',
        }
        self.doc_paths = {f'{directory}/{name}':name for directory in ('/root', '/srv/company') for name in documents.FILES}
        self.prepared = {}
        self.dirs.update({'/srv/company/finance','/srv/company/operations','/srv/company/reports','/srv/company/archive'})
        self.files['/srv/company/README.txt'] = b'Aegis Systems - Corporate Archive\nfinance/ - annual financial statements\nreports/ - company overview\noperations/ - service inventory\narchive/ - prior period notes\nSynthetic records for the KARMA lab.\n'
        self.files['/srv/company/operations/services.csv'] = b'service,owner,status\nCustomer Portal,Platform Team,Active\nBilling,Finance Systems,Active\n'
        self.files['/srv/company/archive/2025-summary.txt'] = b'FY2025 archive index\nQuarterly reports consolidated into the annual financial statement.\n'
        self.doc_paths['/srv/company/finance/company_financials_25-26.xlsx'] = 'company_financials_25-26.xlsx'
        self.doc_paths['/srv/company/reports/company_data_2026.pdf'] = 'company_data_2026.pdf'
        self.read_notified = set()
        self.history = []
        self.last_activity = time.monotonic()
        self.open_handles = 0

    @property
    def prompt(self):
        return f'root@aegis-gateway:{"~" if self.cwd == "/root" else self.cwd}# '

    def path(self, value):
        self.last_activity = time.monotonic()
        if not isinstance(value, str) or len(value) > 1024 or '\x00' in value:
            raise ValueError('Invalid path')
        if value == '~' or value.startswith('~/'):
            value = '/root' + value[1:]
        # POSIX normalization is for virtual dictionary keys only. No host path resolution.
        return '/' + posixpath.normpath(posixpath.join(self.cwd, value)).lstrip('/')

    def names(self, directory):
        directory = self.path(directory)
        if directory not in self.dirs:
            raise FileNotFoundError(directory)
        return sorted({posixpath.basename(p) for p in self.dirs | self.files.keys() | self.doc_paths.keys()
                       if p != directory and posixpath.dirname(p) == directory})

    def read(self, path, notify=True):
        path = self.path(path)
        if path in self.doc_paths:
            name = self.doc_paths[path]
            if name not in self.prepared:
                self.prepared[name] = documents.issue_document(name, self.ip, self.session, self.base)
            if notify and name not in self.read_notified:
                documents.record_document_event(name, self.ip, self.session, self.ip, broadcast=self.broadcast, port=self.document_port)
                self.read_notified.add(name)
            return self.prepared[name]
        if path not in self.files:
            raise FileNotFoundError(path)
        return self.files[path]

    def attributes(self, path):
        path = self.path(path)
        attr = paramiko.SFTPAttributes()
        attr.filename = posixpath.basename(path)
        attr.st_uid = attr.st_gid = 0
        attr.st_atime = attr.st_mtime = 1790812800
        if path in self.dirs:
            attr.st_mode, attr.st_size = stat.S_IFDIR | 0o755, 4096
        else:
            attr.st_mode, attr.st_size = stat.S_IFREG | 0o644, len(self.read(path, notify=False))
        return attr

    def execute(self, command):
        if len(command) > 8192:
            return 'bash: command exceeds limit\n', 2
        self.history.append(command)
        self.history = self.history[-100:]
        try:
            lexer = shlex.shlex(command, posix=True, punctuation_chars=';&|<>')
            lexer.whitespace_split = True
            parts = list(lexer)
            if not parts:
                return '', 0
            if any(p and all(c in ';&|<>' for c in p) for p in parts):
                return 'bash: compound commands, pipelines and redirection are not supported in this lab shell\n', 2
            name, args = parts[0], parts[1:]
            paths = [a for a in args if not a.startswith('-')]
            if name in ('exit','quit','true'): return '', 0
            if name == 'false': return '', 1
            if name == 'pwd': return self.cwd+'\n', 0
            if name == 'whoami': return 'root\n', 0
            if name == 'id': return 'uid=0(root) gid=0(root) groups=0(root)\n', 0
            if name == 'hostname': return 'aegis-gateway\n', 0
            if name == 'uname': return 'Linux aegis-gateway 5.15.0-76-generic x86_64 GNU/Linux\n', 0
            if name == 'date': return time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())+'\n', 0
            if name in ('env','printenv'): return 'USER=root\nHOME=/root\nSHELL=/bin/bash\nPATH=/usr/bin:/bin\n', 0
            if name == 'echo': return ' '.join(args)+'\n', 0
            if name == 'history': return '\n'.join(f'{i+1}  {s}' for i,s in enumerate(self.history))+'\n', 0
            if name == 'clear': return '\x1b[2J\x1b[H', 0
            if name == 'cd':
                target = self.path(paths[0] if paths else '/root')
                if target not in self.dirs: raise FileNotFoundError(target)
                self.cwd = target
                return '', 0
            if name in ('ls','dir'):
                target = self.path(paths[0] if paths else '.')
                items = [posixpath.join(target,n) for n in self.names(target)] if target in self.dirs else [target]
                lines = []
                for p in items:
                    attr = self.attributes(p)
                    label = posixpath.basename(p) + ('/' if p in self.dirs else '')
                    lines.append(f'{stat.filemode(attr.st_mode)} 1 root root {attr.st_size:8} Oct 01 00:00 {label}' if any('l' in a for a in args if a.startswith('-')) else label)
                return '\n'.join(lines)+'\n', 0
            if name in ('find','tree'):
                root = self.path(paths[0] if paths else '.')
                if root not in self.dirs: raise FileNotFoundError(root)
                pattern = args[args.index('-name')+1] if '-name' in args else '*'
                entries = sorted(self.dirs | self.files.keys() | self.doc_paths.keys())
                return '\n'.join(p for p in entries if (p == root or p.startswith(root.rstrip('/')+'/')) and fnmatch.fnmatch(posixpath.basename(p),pattern))+'\n', 0
            if name in ('cat','head','tail','wc','grep'):
                if not paths: return f'{name}: file operand required\n', 2
                target = paths[-1]
                data = self.read(target)
                if name == 'wc': return f'{len(data.splitlines())} {len(data.split())} {len(data)} {target}\n', 0
                if self.path(target) in self.doc_paths or b'\x00' in data[:1024]:
                    return f'{target}: binary document; download using SFTP\n', 0
                text = data.decode('utf-8',errors='replace')
                lines = text.splitlines(keepends=True)
                if name == 'head': text=''.join(lines[:10])
                if name == 'tail': text=''.join(lines[-10:])
                if name == 'grep':
                    if len(paths)<2: return 'grep: pattern and file required\n',2
                    text=''.join(line for line in lines if paths[0] in line)
                return text[:65536], 0
            if name in ('file','stat'):
                p = self.path(paths[0])
                a = self.attributes(p)
                kind = 'directory' if p in self.dirs else ('PDF document' if p.endswith('.pdf') else 'Microsoft Excel 2007+' if p.endswith('.xlsx') else 'text')
                return f'{p}: {kind}, {a.st_size} bytes, {stat.filemode(a.st_mode)}\n', 0
            if name in ('mkdir','touch','cp','mv','rm','rmdir'):
                if not paths: return f'{name}: missing operand\n',2
                if len(self.files)+len(self.dirs)+len(self.doc_paths) >= 128: return 'bash: session file quota reached\n',1
                p = self.path(paths[0])
                if name in ('mkdir','touch'):
                    if posixpath.dirname(p) not in self.dirs: raise FileNotFoundError(posixpath.dirname(p))
                    if p in self.dirs or p in self.doc_paths or p in self.files: return f'{name}: path already exists\n',1
                    if name == 'mkdir': self.dirs.add(p)
                    else: self.files[p]=b''
                elif name in ('cp','mv'):
                    target = self.path(paths[1])
                    if target in self.dirs: target = posixpath.join(target,posixpath.basename(p))
                    if target in self.doc_paths or target in self.dirs: return 'bash: protected destination\n',1
                    if posixpath.dirname(target) not in self.dirs: raise FileNotFoundError(target)
                    content = self.read(p)
                    if sum(map(len,self.files.values()))+len(content)>2*1024*1024: return 'bash: session byte quota reached\n',1
                    self.files[target]=content
                    if name=='mv': self.files.pop(p,None); self.doc_paths.pop(p,None)
                elif name=='rm':
                    if p not in self.files and p not in self.doc_paths: raise FileNotFoundError(p)
                    self.files.pop(p,None); self.doc_paths.pop(p,None)
                else:
                    if p in ('/','/root',self.cwd) or self.names(p): return 'rmdir: directory is not empty or is in use\n',1
                    self.dirs.remove(p)
                return '',0
            if name == 'help':
                return 'Commands: ls cd pwd cat head tail grep wc find tree file stat whoami id uname hostname date env echo history clear mkdir touch cp mv rm rmdir exit\nSFTP downloads are read-only. No host command execution.\n',0
            return f'bash: {name}: command not found\n',127
        except (ValueError,IndexError,FileNotFoundError) as exc:
            return f'bash: {str(exc)[:256] or "invalid arguments"}\n',1


class VirtualHandle(paramiko.SFTPHandle):
    def __init__(self, shell, path):
        super().__init__()
        self.shell,self.path = shell,path
        self.closed = False
        self.shell.open_handles += 1

    def close(self):
        if not self.closed:
            self.shell.open_handles -= 1
            self.closed = True
        return paramiko.SFTP_OK

    def read(self, offset, length):
        if db.is_quarantined(self.shell.ip): return paramiko.SFTP_PERMISSION_DENIED
        if offset<0 or length<0: return paramiko.SFTP_FAILURE
        try:
            data = self.shell.read(self.path,notify=False)[offset:offset+min(length,65536)]
            if data:
                self.shell.read(self.path,notify=True)
            return data
        except FileNotFoundError:
            return paramiko.SFTP_NO_SUCH_FILE

    def stat(self): return self.shell.attributes(self.path)


class VirtualSFTP(paramiko.SFTPServerInterface):
    def __init__(self, server, *args, **kwargs):
        super().__init__(server,*args,**kwargs)
        self.shell = server.shell

    def canonicalize(self,path): return self.shell.path(path)

    def list_folder(self,path):
        if db.is_quarantined(self.shell.ip): return paramiko.SFTP_PERMISSION_DENIED
        try: return [self.shell.attributes(posixpath.join(self.shell.path(path),n)) for n in self.shell.names(path)]
        except (ValueError,FileNotFoundError): return paramiko.SFTP_NO_SUCH_FILE

    def stat(self,path):
        if db.is_quarantined(self.shell.ip): return paramiko.SFTP_PERMISSION_DENIED
        try: return self.shell.attributes(path)
        except (ValueError,FileNotFoundError): return paramiko.SFTP_NO_SUCH_FILE

    lstat = stat

    def open(self,path,flags,attr):
        if self.shell.open_handles >= 32: return paramiko.SFTP_FAILURE
        if flags & (os.O_WRONLY|os.O_RDWR|os.O_APPEND|os.O_CREAT|os.O_TRUNC|os.O_EXCL): return paramiko.SFTP_PERMISSION_DENIED
        if db.is_quarantined(self.shell.ip): return paramiko.SFTP_PERMISSION_DENIED
        try:
            self.shell.read(path,notify=False)
            return VirtualHandle(self.shell,self.shell.path(path))
        except (ValueError,FileNotFoundError): return paramiko.SFTP_NO_SUCH_FILE
