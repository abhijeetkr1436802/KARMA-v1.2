"""Read-only FTP decoy with virtual files and peer-bound data connections."""
import posixpath
import socket
import stat
import time

from backend import config, database as db
from backend.sensors.tcp_server import BoundedTCPServer
from backend.sensors.virtual_shell import VirtualShell


class FTPHoneypotServer(BoundedTCPServer):
    service = "FTP_HONEYPOT"
    def __init__(self, host=config.SENSOR_HOST, port=21, broadcast_callback=None):
        super().__init__(port, self.handle, host)
        self.broadcast = broadcast_callback

    def handle(self, control, ip):
        shell = VirtualShell(ip, control.getsockname()[0], self.broadcast)
        shell.document_port = self.port
        shell.cwd = '/srv/company'
        passive = None
        active = None
        user = None
        authenticated = False
        deadline = time.monotonic() + 1800
        def reply(message):
            control.sendall((message+'\r\n').encode('utf-8'))
        def close_data():
            nonlocal passive, active
            if passive:
                with self.lock:
                    self.clients.discard(passive)
                passive.close()
                passive = None
            active = None
        def transfer(content):
            nonlocal passive, active
            if not passive and not active:
                reply('425 Use PORT, EPRT, PASV or EPSV first.')
                return
            data = None
            reply('150 Opening data connection.')
            try:
                if passive:
                    data, peer = passive.accept()
                    if peer[0] != ip:
                        raise OSError('Data peer mismatch')
                else:
                    data = socket.create_connection(active, timeout=10)
                data.settimeout(10)
                with self.lock:
                    self.clients.add(data)
                if db.is_quarantined(ip):
                    raise OSError('Client blocked')
                data.sendall(content)
                data.close()
                reply('226 Transfer complete.')
            except OSError:
                reply('425 Data connection failed; check client firewall or data mode.')
            finally:
                if data:
                    with self.lock:
                        self.clients.discard(data)
                    data.close()
                close_data()
        # Log the bare connection too, so connect scans (nmap -sT/-sV) show up before any command.
        from backend.engine.threat_score import calculate_event_risk
        score, severity = calculate_event_risk(40, db.get_attempt_count(ip) + 1)
        event = db.log_attack_event(ip, self.port, 'FTP_HONEYPOT', 'FTP connection / service discovery',
                                    'TCP connection to FTP service', 'T1046', 'Network Service Discovery',
                                    'Discovery', score, severity)
        if self.broadcast:
            self.broadcast({'id': event})
        reply(config.FTP_BANNER)
        try:
            with control.makefile('rb') as reader:
                while self.running and not db.is_quarantined(ip) and time.monotonic() < deadline:
                    control.settimeout(min(600, max(0.1,deadline-time.monotonic())))
                    line = reader.readline(8193)
                    if not line:
                        break
                    if len(line)>8192:
                        reply('500 Command too long.')
                        break
                    command, _, arg = line.decode('utf-8',errors='replace').strip().partition(' ')
                    command, arg = command.upper(), arg.strip()
                    if command=='RETR':  # file download = data collection, not just browsing
                        score, severity = calculate_event_risk(60, db.get_attempt_count(ip) + 1)
                        mitre = ('T1005', 'Data from Local System', 'Collection')
                    else:
                        score, severity, mitre = 25, 'LOW', ('', '', '')
                    event = db.log_attack_event(ip,self.port,'FTP_HONEYPOT','FTP command',
                        command + (' [redacted]' if command=='PASS' else ' '+arg), *mitre, score, severity)
                    if self.broadcast:
                        self.broadcast({'id':event})
                    if command=='QUIT':
                        reply('221 Goodbye.')
                        break
                    if command=='USER':
                        user, authenticated = arg, False
                        close_data()
                        reply('331 Please specify the password.')
                    elif command=='PASS':
                        if not user:
                            reply('503 Send USER first.')
                        else:
                            authenticated = True
                            reply('230 User logged in, proceed.')
                    elif command=='SYST': reply('215 UNIX Type: L8')
                    elif command=='FEAT': reply('211-Features\r\n UTF8\r\n EPSV\r\n EPRT\r\n SIZE\r\n MDTM\r\n211 End')
                    elif command=='OPTS': reply('200 UTF8 enabled.' if arg.upper()=='UTF8 ON' else '501 Unsupported option.')
                    elif command=='NOOP': reply('200 OK')
                    elif command=='HELP': reply('214 USER PASS PWD CWD CDUP LIST NLST TYPE PORT EPRT PASV EPSV RETR SIZE MDTM QUIT. Read-only archive.')
                    elif not authenticated: reply('530 Please log in with USER and PASS.')
                    elif command in ('PWD','XPWD'): reply('257 "'+shell.cwd.replace('"','""')+'" is current directory.')
                    elif command in ('CWD','XCWD','CDUP','XCUP'):
                        path = shell.path('..' if command in ('CDUP','XCUP') else arg)
                        if path not in shell.dirs: reply('550 Directory not found.')
                        else:
                            shell.cwd = path
                            reply('250 Directory changed.')
                    elif command=='TYPE': reply('200 Type set.' if arg.upper() in ('I','A','A N') else '504 Unsupported type.')
                    elif command in ('PASV','EPSV'):
                        close_data()
                        passive = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                        passive.bind((control.getsockname()[0],0))
                        passive.listen(1)
                        passive.settimeout(10)
                        with self.lock:
                            self.clients.add(passive)
                        port=passive.getsockname()[1]
                        if command=='EPSV': reply(f'229 Entering Extended Passive Mode (|||{port}|)')
                        else: reply('227 Entering Passive Mode ('+control.getsockname()[0].replace('.',',')+f',{port//256},{port%256})')
                    elif command in ('PORT','EPRT'):
                        close_data()
                        try:
                            if command=='PORT':
                                parts=[int(p) for p in arg.split(',')]
                                if len(parts)!=6 or any(p<0 or p>255 for p in parts): raise ValueError()
                                host='.'.join(map(str,parts[:4])); port=parts[4]*256+parts[5]
                            else:
                                parts=arg.split(arg[0])
                                if len(parts)!=5 or parts[1]!='1': raise ValueError()
                                host,port=parts[2],int(parts[3])
                            if host!=ip or not 1024<=port<=65535: raise ValueError()
                            active=(host,port)
                            reply('200 Data endpoint accepted.')
                        except (ValueError,IndexError): reply('501 Data endpoint must be this client and an unprivileged port.')
                    elif command in ('LIST','NLST','RETR','SIZE','MDTM'):
                        try:
                            path=shell.path('.' if not arg or arg.startswith('-') else arg)
                            if command in ('LIST','NLST'):
                                paths=[posixpath.join(path,n) for n in shell.names(path)] if path in shell.dirs else [path]
                                lines=[]
                                for p in paths:
                                    attr=shell.attributes(p)
                                    name=posixpath.basename(p)
                                    lines.append(name if command=='NLST' else f'{stat.filemode(attr.st_mode)} 1 admin staff {attr.st_size:8} Oct 01 00:00 {name}')
                                transfer(('\r\n'.join(lines)+'\r\n').encode())
                            elif command=='SIZE': reply(f'213 {len(shell.read(path,notify=False))}')
                            elif command=='MDTM':
                                shell.attributes(path)
                                reply('213 20261001000000')
                            elif not active and not passive: reply('425 Set up a data connection first.')
                            else: transfer(shell.read(path))
                        except (ValueError,FileNotFoundError):
                            close_data()
                            reply('550 File or directory not found.')
                    elif command in ('STOR','APPE','DELE','RMD','MKD','RNFR','RNTO','SITE'): reply('550 Archive is read-only.')
                    else: reply('502 Command not implemented; use HELP for supported commands.')
        except (OSError,ValueError):
            pass
        finally:
            close_data()
