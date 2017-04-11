from __future__ import unicode_literals

from contextlib import closing
import io
import os.path
from shutil import rmtree
import sqlite3
from tempfile import mkdtemp
import unittest
from wsgiref.headers import Headers
from wsgiref.util import FileWrapper, setup_testing_defaults
from wsgiref.validate import validator

import wsgir


class WSGIrTestCase(unittest.TestCase):
    def setUp(self):
        os.environ['WSGIR_DEBUG'] = '1'
        self.environ = {'QUERY_STRING': b''}
        setup_testing_defaults(self.environ)
        self.start_response = Mock()
        self.temp_dir = mkdtemp()

    def tearDown(self):
        rmtree(self.temp_dir)

    def test_get_app(self):
        app = validator(wsgir.app)
        with closing(app(self.environ, self.start_response)) as response:
            body = next(response)
            self.assertIn(b'<!doctype html>', body)
            self.assertIn(b'<title>WSGIr</title>', body)
        self.assertEqual(len(self.start_response.called), 1)
        (status, headers), _kwargs = self.start_response.called[0]
        headers = Headers(headers)
        self.assertEqual(status, b'200 OK')
        self.assertEqual(headers['Content-Type'], b'text/html; charset="UTF-8"')

    def test_get_show_entries_when_logged_in(self):
        self.init_environ()
        self.login()
        app = validator(wsgir.show_entries)
        with closing(app(self.environ, self.start_response)) as response:
            body = next(response)
            self.assertIn(b'<!doctype html>', body)
            self.assertIn(b'<title>WSGIr</title>', body)
            self.assertIn(b'</form>', body)
        self.assertEqual(len(self.start_response.called), 1)
        (status, headers), _kwargs = self.start_response.called[0]
        headers = Headers(headers)
        self.assertEqual(status, b'200 OK')
        self.assertEqual(len(headers.get_all('Set-Cookie')), 1)
        self.assertEqual(headers['Content-Type'], b'text/html; charset="UTF-8"')

    def test_get_show_entries_when_not_logged_in(self):
        self.init_environ()
        app = validator(wsgir.show_entries)
        with closing(app(self.environ, self.start_response)) as response:
            body = next(response)
            self.assertIn(b'<!doctype html>', body)
            self.assertIn(b'<title>WSGIr</title>', body)
            self.assertNotIn(b'</form>', body)
        self.assertEqual(len(self.start_response.called), 1)
        (status, headers), _kwargs = self.start_response.called[0]
        headers = Headers(headers)
        self.assertEqual(status, b'200 OK')
        self.assertEqual(len(headers.get_all('Set-Cookie')), 1)
        self.assertEqual(headers['Content-Type'], b'text/html; charset="UTF-8"')

    def test_get_add_entry(self):
        self.init_environ()
        app = validator(wsgir.add_entry)
        with closing(app(self.environ, self.start_response)) as response:
            self.assertEqual(next(response), b'Method Not Allowed\n')
        self.assertEqual(len(self.start_response.called), 1)
        (status, headers), _kwargs = self.start_response.called[0]
        self.assertEqual(status, b'405 Method Not Allowed')
        headers = Headers(headers)
        self.assertEqual(headers['Content-Type'], b'text/plain; charset="UTF-8"')
        self.assertIn(b'POST', headers['Allow'])

    def test_post_add_entry_when_logged_in(self):
        self.init_environ({
            'REQUEST_METHOD': b'POST',
            'wsgi.input': io.BytesIO(b'title=title&text=text'),
        })
        self.login()
        app = validator(wsgir.add_entry)
        with closing(app(self.environ, self.start_response)) as response:
            self.assertRaises(StopIteration, next, response)
        self.assertEqual(len(self.start_response.called), 1)
        (status, headers), _kwargs = self.start_response.called[0]
        headers = Headers(headers)
        self.assertEqual(status, b'303 See Other')
        self.assertEqual(len(headers.get_all('Set-Cookie')), 1)
        self.assertEqual(headers['Content-Type'], b'text/plain; charset="UTF-8"')
        self.assertEqual(headers['Location'], b'/')

    def test_post_add_entry_when_not_logged_in(self):
        self.init_environ({
            'REQUEST_METHOD': b'POST',
            'wsgi.input': io.BytesIO(b'title=title&text=text'),
        })
        app = validator(wsgir.add_entry)
        with closing(app(self.environ, self.start_response)) as response:
            self.assertEqual(next(response), b'Unauthorized\n')
        self.assertEqual(len(self.start_response.called), 1)
        (status, headers), _kwargs = self.start_response.called[0]
        headers = Headers(headers)
        self.assertEqual(status, b'401 Unauthorized')
        self.assertEqual(headers['Content-Type'], b'text/plain; charset="UTF-8"')

    def test_connect_db(self):
        self.init_environ()
        db = wsgir.connect_db(self.environ)
        self.assertIsInstance(db, sqlite3.Connection)
        self.assertEqual(db.row_factory, sqlite3.Row)

    def test_init_db(self):
        self.init_environ()
        wsgir.init_db(self.environ)
        with closing(sqlite3.connect(self.environ['wsgir.database'])) as db:
            cursor = db.execute('select * from sqlite_master')
            self.assertIn('CREATE TABLE entries', repr(cursor.fetchall()))

    def test_render(self):
        self.init_environ()
        self.environ['wsgir.template_dir'] = self.temp_dir
        template_name = 'example.html'
        template_path = os.path.join(self.environ['wsgir.template_dir'],
                                     template_name)
        with open(template_path, 'w') as f:
            f.write('<!doctype html><title>{title}</title>\n')
        html = wsgir.render(self.environ, template_name, title='title')
        self.assertEqual('<!doctype html><title>title</title>\n', html)

    def test_get_file_wrapper(self):
        file_wrapper = wsgir.get_file_wrapper({})
        self.assertEqual(file_wrapper, FileWrapper)
        file_wrapper = wsgir.get_file_wrapper({'wsgi.file_wrapper': None})
        self.assertEqual(file_wrapper, FileWrapper)
        stub_file_wrapper = object()
        file_wrapper = wsgir.get_file_wrapper({'wsgi.file_wrapper': stub_file_wrapper})
        self.assertEqual(file_wrapper, stub_file_wrapper)

    def test_modified_since(self):
        since = 'Thu, 01 Jan 1970 00:00:01 GMT'
        rv = wsgir.modified_since({}, 0)
        self.assertTrue(rv)
        rv = wsgir.modified_since({'HTTP_IF_MODIFIED_SINCE': since}, 0)
        self.assertTrue(rv)
        rv = wsgir.modified_since({'HTTP_IF_MODIFIED_SINCE': since}, 1)
        self.assertTrue(rv)
        rv = wsgir.modified_since({'HTTP_IF_MODIFIED_SINCE': since}, 2)
        self.assertFalse(rv)

    def test_get_session(self):
        self.init_environ()
        session = wsgir.get_session(self.environ)
        self.assertEqual(session, {})

    def test_decode_session(self):
        key = 'secret'
        invalid_session_string = 'invalid session'
        rv = wsgir.decode_session(invalid_session_string, key)
        self.assertIsNone(rv)
        invalid_session_string = 'invalid.session'
        rv = wsgir.decode_session(invalid_session_string, key)
        self.assertIsNone(rv)

    def test_compare_digest(self):
        self.assertTrue(wsgir.compare_digest('foo', 'foo'))
        self.assertFalse(wsgir.compare_digest('foo', 'bar'))

    def test_safe_join(self):
        self.assertIsNone(wsgir.safe_join('/var/www', '/etc/passwd'))
        self.assertIsNone(wsgir.safe_join('/var/www', '../etc/passwd'))
        self.assertEqual(wsgir.safe_join('/var/www', 'etc/passwd'), '/var/www/etc/passwd')

    def init_environ(self, kwargs=None):
        self.environ = wsgir.init_environ(self.environ)
        self.environ['wsgir.debug'] = True
        self.environ['wsgir.database'] = os.path.join(self.temp_dir, 'test.db')
        if kwargs is not None:
            self.environ.update(kwargs)
        wsgir.init_db(self.environ)

    def login(self):
        session = wsgir.get_session(self.environ)
        session['logged_in'] = True
        headers = wsgir.make_session_headers(self.environ, session)
        self.environ['HTTP_COOKIE'] = headers['Set-Cookie']


class Mock(object):
    def __init__(self):
        self.called = []

    def __getattr__(self, key):
        return Mock()

    def __call__(self, *args, **kwargs):
        self.called.append((args, kwargs))


if __name__ == '__main__':
    unittest.main()
