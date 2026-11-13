"""Имитация Firebase для локальной проверки: Identity Toolkit + securetoken + Firestore REST (people/*).
Пользователи заводятся заранее (как в консоли), правила: читать и писать свой документ могут только из ALLOW."""
import json, sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

USERS = {'a@test.ru': ('pass-a', 'uidA'), 'b@test.ru': ('pass-b', 'uidB'), 'x@test.ru': ('pass-x', 'uidX')}
ALLOW = {'a@test.ru', 'b@test.ru'}
DOCS = {}
LOG = []


def email_of(uid):
    return next(e for e, (_, u) in USERS.items() if u == uid)


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def send(self, code, obj=None):
        body = json.dumps(obj if obj is not None else {}).encode()
        self.send_response(code)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Headers', 'Authorization, Content-Type')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, PATCH, OPTIONS')
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def err(self, code, msg):
        self.send(code, {'error': {'code': code, 'message': msg}})

    def body(self):
        n = int(self.headers.get('Content-Length') or 0)
        return self.rfile.read(n).decode()

    def user(self):
        a = self.headers.get('Authorization', '')
        if not a.startswith('Bearer tok-'):
            return None
        uid = a[len('Bearer tok-'):].split('~')[0]
        return uid if any(u == uid for _, u in USERS.values()) else None

    def do_OPTIONS(self):
        self.send(204)

    def do_POST(self):
        u = urlparse(self.path)
        LOG.append(('POST', u.path))
        if u.path == '/auth/signInWithPassword':
            d = json.loads(self.body())
            rec = USERS.get(d.get('email'))
            if not rec or rec[0] != d.get('password'):
                return self.err(400, 'INVALID_LOGIN_CREDENTIALS')
            uid = rec[1]
            return self.send(200, {'localId': uid, 'email': d['email'], 'idToken': 'tok-' + uid + '~1', 'refreshToken': 'ref-' + uid, 'expiresIn': '3600'})
        if u.path == '/token':
            q = parse_qs(self.body())
            rt = q.get('refresh_token', [''])[0]
            if not rt.startswith('ref-'):
                return self.err(400, 'INVALID_REFRESH_TOKEN')
            uid = rt[4:]
            return self.send(200, {'id_token': 'tok-' + uid + '~2', 'refresh_token': rt, 'expires_in': '3600'})
        self.err(404, 'NOT_FOUND')

    def do_GET(self):
        u = urlparse(self.path)
        LOG.append(('GET', u.path))
        if u.path == '/_log':
            return self.send(200, LOG)
        if u.path == '/_reset':
            DOCS.clear(); LOG.clear()
            return self.send(200)
        uid = self.user()
        if not uid or email_of(uid) not in ALLOW:
            return self.err(403, 'Missing or insufficient permissions.')
        if u.path == '/db/people':
            docs = [dict(name='projects/p/databases/(default)/documents/people/' + k, fields=v) for k, v in DOCS.items()]
            return self.send(200, {'documents': docs} if docs else {})
        if u.path.startswith('/db/people/'):
            k = u.path.rsplit('/', 1)[1]
            if k not in DOCS:
                return self.err(404, 'NOT_FOUND')
            return self.send(200, dict(name='projects/p/databases/(default)/documents/people/' + k, fields=DOCS[k]))
        self.err(404, 'NOT_FOUND')

    def do_PATCH(self):
        u = urlparse(self.path)
        LOG.append(('PATCH', u.path))
        uid = self.user()
        k = u.path.rsplit('/', 1)[1]
        if not uid or email_of(uid) not in ALLOW or k != uid:
            return self.err(403, 'Missing or insufficient permissions.')
        DOCS[k] = json.loads(self.body())['fields']
        self.send(200, dict(name='projects/p/databases/(default)/documents/people/' + k, fields=DOCS[k]))


ThreadingHTTPServer(('127.0.0.1', int(sys.argv[1])), H).serve_forever()
