import ftplib
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from backend import database as db
from backend.sensors.ftp_honeypot import FTPHoneypotServer


class FTPTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.patch=patch.object(db,'DB_PATH',str(Path(self.temp.name)/'test.db'))
        self.patch.start()
        db.init_db()
        self.server=FTPHoneypotServer(host='127.0.0.1',port=0)
        self.server.start()
        self.ftp=ftplib.FTP()
        self.ftp.connect('127.0.0.1',self.server.server_socket.getsockname()[1],timeout=5)

    def tearDown(self):
        self.ftp.close()
        self.server.stop()
        self.patch.stop()
        self.temp.cleanup()

    def test_login_listing_navigation_and_download_both_modes(self):
        with self.assertRaises(ftplib.error_perm): self.ftp.pwd()
        self.ftp.login('Admin','test-password-never-log')
        self.assertEqual(self.ftp.pwd(),'/srv/company')
        for passive in (True,False):
            self.ftp.set_pasv(passive)
            self.assertIn('finance',self.ftp.nlst())
            lines=[]
            self.ftp.retrlines('LIST',lines.append)
            self.assertTrue(any('reports' in line for line in lines))
            self.ftp.cwd('reports')
            data=io.BytesIO()
            self.ftp.retrbinary('RETR company_data_2026.pdf',data.write)
            self.assertTrue(data.getvalue().startswith(b'%PDF'))
            self.assertEqual(self.ftp.size('company_data_2026.pdf'),len(data.getvalue()))
            self.ftp.cwd('..')
        self.assertTrue(all('test-password-never-log' not in event['payload'] for event in db.get_recent_logs()))
        self.ftp.quit()

    def test_no_bounce_upload_or_host_files(self):
        self.ftp.login('Admin','dummy')
        for command in ('PORT 8,8,8,8,200,1','PORT 127,0,0,1,0,22','EPRT |1|8.8.8.8|5000|','STOR upload.txt','RETR /Windows/win.ini','CWD /Windows'):
            if command.startswith('RETR'):
                self.ftp.sendcmd('PASV')
            with self.assertRaises(ftplib.error_perm, msg=command):
                self.ftp.sendcmd(command)
        self.assertEqual(self.ftp.sendcmd('XPWD'),'257 "/srv/company" is current directory.')
        self.assertTrue(self.ftp.sendcmd('EPSV').startswith('229'))
