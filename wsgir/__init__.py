from __future__ import unicode_literals

from base64 import b64decode, b64encode
try:
    import builtins
except ImportError:
    import __builtin__ as builtins
from cgi import FieldStorage
from contextlib import closing
from email.utils import formatdate, mktime_tz, parsedate_tz
import hashlib
import hmac
try:
    from html import escape
except ImportError:
    from cgi import escape
try:
    from http.cookies import SimpleCookie
except ImportError:
    from Cookie import SimpleCookie
import logging
from mimetypes import guess_type
import os
try:
    import cPickle as pickle
except ImportError:
    import pickle
from posixpath import normpath
import re
import sqlite3
from string import Formatter
from wsgiref.headers import Headers
from wsgiref.util import FileWrapper, guess_scheme


def app(environ, start_response):
    environ = init_environ(environ)
    if environ['wsgir.debug']:
        from wsgiref.validate import validator
        return validator(route)(environ, start_response)
    return route(environ, start_response)


def route(environ, start_response):
    url_map = [
        (r'^$', show_entries),
        (r'^add/?$', add_entry),
        (r'^login/?$', login),
        (r'^logout/?$', logout),
        (r'^static/(.*)$', static),
    ]
    path = environ['PATH_INFO'].lstrip('/')
    for pattern, callback in url_map:
        matched = re.search(pattern, path)
        if matched is not None:
            environ['wsgir.url_args'] = matched.groups()
            return callback(environ, start_response)
    return not_found(environ, start_response)


def show_entries(environ, start_response):
    with closing(connect_db(environ)) as db:
        cursor = db.execute('select title, text from entries order by id desc')
        entries = cursor.fetchall()
    session = get_session(environ)
    flashes = session.pop('flashes', [])
    headers = make_session_headers(environ, session)
    headers.add_header(b'Content-Type', b'text/html', charset=b'UTF-8')
    start_response(b'200 OK', headers.items())
    body = render(environ, 'show_entries.html', entries=entries)
    return [render(environ, 'layout.html', body=body, flashes=flashes)]


def add_entry(environ, start_response):
    method = environ['REQUEST_METHOD']
    if method == 'POST':
        session = get_session(environ)
        if not session.get('logged_in'):
            return unauthorized(environ, start_response)
        form = FieldStorage(fp=environ['wsgi.input'], environ=environ)
        with closing(connect_db(environ)) as db, db:
            db.execute('insert into entries (title, text) values (?, ?)',
                       [form.getfirst('title'), form.getfirst('text')])
        session.setdefault('flashes', [])
        session['flashes'].append('New entry was successfully posted')
        headers = make_session_headers(environ, session)
        headers.add_header(b'Content-Type', b'text/plain', charset=b'UTF-8')
        headers.add_header(b'Location', b'/')
        start_response(b'303 See Other', headers.items())
        return []
    return make_method_not_allowed('POST')(environ, start_response)


def login(environ, start_response):
    error = None
    method = environ['REQUEST_METHOD']
    session = get_session(environ)
    if method == 'POST':
        form = FieldStorage(fp=environ['wsgi.input'], environ=environ)
        if form.getfirst('username') != environ['wsgir.username']:
            error = 'Invalid username'
        elif form.getfirst('password') != environ['wsgir.password']:
            error = 'Invalid password'
        else:
            session['logged_in'] = True
            session.setdefault('flashes', [])
            session['flashes'].append('You were logged in')
            headers = make_session_headers(environ, session)
            headers.add_header(b'Content-Type', b'text/plain',
                               charset=b'UTF-8')
            headers.add_header(b'Location', b'/')
            start_response(b'302 Found', headers.items())
            return []
    flashes = session.pop('flashes', [])
    headers = make_session_headers(environ, session)
    headers.add_header(b'Content-Type', b'text/html')
    start_response(b'200 OK', headers.items())
    body = render(environ, 'login.html', error=error)
    return [render(environ, 'layout.html', body=body, flashes=flashes)]


def logout(environ, start_response):
    session = get_session(environ)
    session.pop('logged_in', None)
    session.setdefault('flashes', [])
    session['flashes'].append('You were logged out')
    headers = make_session_headers(environ, session)
    headers.add_header(b'Content-Type', b'text/plain', charset=b'UTF-8')
    headers.add_header(b'Location', b'/')
    start_response(b'302 Found', headers.items())
    return []


def static(environ, start_response):
    filename = environ['wsgir.url_args'][0]
    path = safe_join(environ['wsgir.static_dir'], filename)
    if path is None:
        return not_found(environ, start_response)
    headers = Headers([])
    max_age = 365 * 24 * 60 * 60
    headers.add_header(b'Cache-Control', b'public, max-age={}'.format(max_age))
    try:
        stat = os.stat(path)
    except (IOError, OSError):
        return not_found(environ, start_response)
    mtime = int(stat.st_mtime)
    last_modified = formatdate(mtime, localtime=False, usegmt=True)
    headers.add_header(b'Last-Modified', bytes(last_modified))
    expires = formatdate(mtime + max_age, localtime=False, usegmt=True)
    headers.add_header(b'Expires', bytes(expires))
    if not modified_since(environ, mtime):
        start_response(b'304 Not Modified', headers.items())
        return []
    mimetype, encoding = guess_type(path)
    headers.add_header(b'Content-Type',
                       bytes(mimetype or b'application/octet-stream'))
    if encoding == 'gzip':
        accept_encoding = environ.get('HTTP_ACCEPT_ENCODING', 'identity')
        if not ((b'gzip' in accept_encoding) or
                (b'deflate' in accept_encoding)):
            return not_acceptable(environ, start_response)
        headers.add_header(b'Content-Encoding', bytes(encoding))
    try:
        f = open(path, 'rb')
    except (IOError, OSError):
        return not_found(environ, start_response)
    start_response(b'200 OK', headers.items())
    file_wrapper = get_file_wrapper(environ)
    return file_wrapper(f)


def unauthorized(environ, start_response):
    start_response(b'401 Unauthorized',
                   [(b'Content-Type', b'text/plain; charset="UTF-8"')])
    return [b'Unauthorized\n']


def not_found(environ, start_response):
    start_response(b'404 Not Found',
                   [(b'Content-Type', b'text/plain; charset="UTF-8"')])
    return [b'Not Found\n']


def make_method_not_allowed(*allow):
    allow = b', '.join(allow)

    def method_not_allowed(environ, start_response):
        start_response(b'405 Method Not Allowed',
                       [(b'Content-Type', b'text/plain; charset="UTF-8"'),
                        (b'Allow', allow)])
        return [b'Method Not Allowed\n']
    return method_not_allowed


def not_acceptable(environ, start_response):
    start_response(b'406 Not Acceptable',
                   [(b'Content-Type', b'text/plain; charset="UTF-8"')])
    return [b'Not Acceptable\n']


def init_environ(environ):
    here = os.path.abspath(os.path.dirname(__file__))
    environ = dict(environ)
    debug = bool(int(os.getenv('WSGIR_DEBUG', 0)))
    environ['wsgir.debug'] = debug
    environ['wsgir.root_dir'] = here
    environ['wsgir.database'] = os.path.join(here, 'wsgir.db')
    log_filename = os.path.join(here, 'wsgir.log')
    environ['wsgir.log_filename'] = log_filename
    environ['wsgir.logger'] = init_logger(debug, log_filename)
    environ['wsgir.secret_key'] = b'secret key'
    environ['wsgir.static_dir'] = os.path.join(here, 'static')
    environ['wsgir.template_dir'] = os.path.join(here, 'templates')
    environ['wsgir.username'] = 'admin'
    environ['wsgir.password'] = 'default'
    return environ


def init_logger(debug, log_filename):
    logger = logging.getLogger(__name__)
    if debug:
        logger.setLevel(logging.DEBUG)
        logger.addHandler(logging.StreamHandler())
    else:
        logger.setLevel(logging.WARNING)
        file_handler = logging.FileHandler(log_filename)
        logger.addHandler(file_handler)
    return logger


def connect_db(environ):
    db = sqlite3.connect(environ['wsgir.database'])
    db.row_factory = sqlite3.Row
    return db


def init_db(environ):
    script_path = os.path.join(environ['wsgir.root_dir'], 'schema.sql')
    with open(script_path, 'r') as f:
        script = f.read()
    with closing(connect_db(environ)) as db, db:
        db.executescript(script)


def render(environ, template_name, _formatter=None, **kwargs):
    template_path = os.path.join(environ['wsgir.template_dir'], template_name)
    with open(template_path, 'r') as f:
        template = f.read()
    if _formatter is None:
        _formatter = TemplateFormatter(environ)
    return bytes(_formatter.format(template, **kwargs))


class TemplateFormatter(Formatter):
    def __init__(self, environ):
        self._environ = environ
        self._globals = dict(
            builtins.__dict__,
            e=self._escape,
            environ=self._environ,
            include=self._include,
            session=get_session(environ),
            )

    def get_field(self, field_name, args, kwargs):
        return eval(field_name, self._globals, kwargs), field_name

    def _escape(self, s):
        return escape(str(s), quote=True)

    def _include(self, template_name):
        return render(self._environ, template_name, _formatter=self)


def get_file_wrapper(environ):
    file_wrapper = environ.get('wsgi.file_wrapper')
    if file_wrapper is None:
        file_wrapper = FileWrapper
    return file_wrapper


def modified_since(environ, mtime):
    since = environ.get('HTTP_IF_MODIFIED_SINCE')
    if since is not None:
        since_timestamp = mktime_tz(parsedate_tz(since))
        return since_timestamp >= mtime
    return True


def get_session(environ):
    cookie_string = environ.get('HTTP_COOKIE', '')
    cookie = SimpleCookie(cookie_string)
    if cookie is not None:
        morsel = cookie.get('wsgir_session')
        if morsel is not None:
            key = environ['wsgir.secret_key']
            return decode_session(morsel.value, key)
    return {}


def make_session_headers(environ, session):
    cookie = SimpleCookie()
    key = environ['wsgir.secret_key']
    cookie[b'wsgir_session'] = encode_session(session, key)
    cookie[b'wsgir_session'][b'domain'] = environ['SERVER_NAME']
    cookie[b'wsgir_session'][b'httponly'] = True
    cookie[b'wsgir_session'][b'max-age'] = 30 * 24 * 60 * 60
    if guess_scheme(environ) == b'https':
        cookie[b'wsgir_session'][b'secure'] = True
    headers = Headers([])
    for line in cookie.output(header='').splitlines():
        headers.add_header(b'Set-Cookie', bytes(line))
    return headers


def decode_session(session_string, key):
    if session_string.count('.') == 1:
        try:
            dumped_session, signature = map(b64decode, session_string.split('.'))
        except TypeError:
            return None
        mac = hmac.new(key, dumped_session, digestmod=hashlib.sha256)
        expected_signature = mac.digest()
        if compare_digest(signature, expected_signature):
            return pickle.loads(dumped_session)


def encode_session(session, key):
    dumped_session = pickle.dumps(session)
    mac = hmac.new(key, dumped_session, digestmod=hashlib.sha256)
    signature = mac.digest()
    return '{}.{}'.format(b64encode(dumped_session), b64encode(signature))


def compare_digest(a, b):
    if hasattr(hmac, 'compare_digest'):
        return hmac.compare_digest(a, b)
    if len(a) != len(b):
        return False
    return a == b


def safe_join(directory, filename):
    filename = normpath(filename)
    for sep in [os.path.sep, os.path.altsep]:
        if sep not in (None, '/') and sep in filename:
            return
    if os.path.isabs(filename) or filename.startswith('../'):
        return
    return os.path.join(directory, filename)
