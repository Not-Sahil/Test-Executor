from http.server import BaseHTTPRequestHandler, HTTPServer
import threading
from urllib.parse import parse_qs
from login_page.scanners.tc04_user_enumeration import scan_user_enumeration
from authentication.enumeration_models import EnumerationConfig

class H(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/login':
            body=b'<html><form method="POST" action="/login"><input name="username"><input name="password" type="password"></form></html>'
            self.send_response(200); self.send_header('Content-Type','text/html'); self.send_header('Content-Length',str(len(body))); self.end_headers(); self.wfile.write(body); return
        self.send_response(404); self.end_headers()
    def do_POST(self):
        if self.path != '/login': self.send_response(404); self.end_headers(); return
        n=int(self.headers.get('Content-Length','0')); data=parse_qs(self.rfile.read(n).decode()); u=data.get('username',[''])[0]
        body,status=(b'Incorrect password',200) if u=='alice' else (b'Invalid username',401)
        self.send_response(status); self.send_header('Content-Type','text/html'); self.send_header('Content-Length',str(len(body))); self.end_headers(); self.wfile.write(body)
    def log_message(self,*args): pass

def test_tc04_local_server():
    srv=HTTPServer(('127.0.0.1',0),H); threading.Thread(target=srv.serve_forever,daemon=True).start()
    try:
        r=scan_user_enumeration('http://127.0.0.1:'+str(srv.server_port), config=EnumerationConfig(login_path='/login',candidate_usernames=('alice','bob'),verify_tls=False))
        assert r['assessment_state']=='CONFIRMED'
        assert r['details']['confirmed_usernames']==['alice']
        assert r['severity'] is not None
        assert r['risk_score'] is not None
    finally:
        srv.shutdown()
