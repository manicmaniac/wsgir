from __future__ import print_function, unicode_literals

from argparse import ArgumentParser
from code import InteractiveConsole
import sys
from wsgiref.simple_server import make_server
from wsgiref.util import setup_testing_defaults

from . import app, init_db, init_environ


def main(argv=None):
    parser = make_argument_parser()
    args = parser.parse_args(argv)
    if args.subcommand == 'initdb':
        initdb_command()
    elif args.subcommand == 'run':
        run_command(args.host, args.port)
    elif args.subcommand == 'shell':
        shell_command()


def make_argument_parser():
    parser = ArgumentParser()
    subparsers = parser.add_subparsers(dest='subcommand')
    subparsers.add_parser('initdb', help='Initializes the database.')
    run_parser = subparsers.add_parser('run',
                                       help='Runs a development server.')
    run_parser.add_argument('-H', '--host', default='localhost')
    run_parser.add_argument('-p', '--port', default=5000, type=int)
    subparsers.add_parser('shell', help='Runs a shell in the app context.')
    return parser


def initdb_command():
    environ = init_environ({})
    init_db(environ)
    print('Initialized the database.', file=sys.stderr)


def run_command(host, port):
    server = make_server(host, port, app)
    print('Starting a server on http://{}:{}.'.format(host, port))
    server.serve_forever()


def shell_command():
    environ = {}
    setup_testing_defaults(environ)
    environ = init_environ(environ)
    console = InteractiveConsole(dict(environ=environ))
    console.interact()


if __name__ == '__main__':
    main()
