#!/usr/bin/env python

import BaseHTTPServer
import SocketServer
import base64
import hashlib
import hmac
import optparse
import re
import signal
import socket
import sys
import threading
import time
import urllib
import urlparse

import status
import validate
import html
from sql import SQL, connect_to_db


class YubiServeHandler:
    def __init__(self, sql_connection, params, vclass):
        self.sql = SQL(sql_connection)
        self.params = params
        self.vclass = vclass

    def sign_message(self, answer, api_key):
        data = ['%s=%s' % (k, v) for (k, v) in answer.iteritems()]
        data.sort()
        data = '&'.join(data)

        otp_hmac = hmac.new(api_key, str(data), hashlib.sha1)
        otp_hmac = base64.b64encode(otp_hmac.digest())

        return otp_hmac

    def build_answer(self, stat, answer, api_key=''):
        answer['status'] = stat
        answer['h'] = self.sign_message(answer, api_key)

        data = '\r\n'.join(['%s=%s' % (k, v) for (k, v) in answer.iteritems()])
        data += '\r\n'

        return data

    def do_validate(self):
        answer = {'t': time.strftime("%Y-%m-%dT%H:%M:%S"), 'otp': ''}

        # API id and OTP are required
        if 'id' not in self.params or 'otp' not in self.params:
            return self.build_answer(status.MISSING_PARAMETER, answer)

        # ensure API id is valid
        if not self.sql.select('get_api_secret', [self.params['id']]):
            return self.build_answer(status.NO_SUCH_CLIENT, answer)

        api_key = base64.b64decode(self.sql.result[0])

        # do token validation
        vclass = self.vclass(self.sql)
        stat = vclass.set_params(self.params, answer)
        if stat == status.OK:
            stat = vclass.validate()
        return self.build_answer(stat, answer, api_key)


class YubiHTTPServer(BaseHTTPServer.BaseHTTPRequestHandler):
    __base = BaseHTTPServer.BaseHTTPRequestHandler
    __base_handle = __base.handle

    server_version = 'YubiKeyedUp/1.0'
    vclasses = {
        '/wsapi/2.0/verify': validate.YubicoOTP,
        '/wsapi/2.0/oathverify': validate.OATH,
    }

    PARAM_REGEXP = {
        'id': '[0-9]{1,3}',
        'otp': '[cbdefghijklnrtuv]{0,16}[cbdefghijklnrtuv]{32}',
        'publicid': '[cbdefghijklnrtuv]{0,16}',
        'nonce': '[a-zA-Z0-9]{16,40}',
    }

    def __init__(self, request, client_address, server):
        global sqlite_db
        self.sql_connection = connect_to_db(sqlite_db)
        return BaseHTTPServer.BaseHTTPRequestHandler.__init__(
                self, request, client_address, server
                )

    def setup(self):
        self.connection = self.request
        self.rfile = socket._fileobject(self.request, 'rb', self.rbufsize)
        self.wfile = socket._fileobject(self.request, 'wb', self.wbufsize)

    def getToDict(self, qs):
        dict = {}
        for singleValue in qs.split('&'):
            if '=' not in singleValue:
                continue
            key, value = singleValue.split('=', 1)
            value = urllib.unquote_plus(value)
            if key in self.PARAM_REGEXP and \
                    re.match(self.PARAM_REGEXP[key], value):
                dict[key] = value
        return dict

    def do_GET(self):
        url = urlparse.urlparse(self.path, 'http')

        if url.path in self.vclasses:
            params = self.getToDict(url.query)
            vclass = self.vclasses[url.path]
            handler = YubiServeHandler(self.sql_connection, params, vclass)
            data = handler.do_validate()
            content_type = 'text/plain'
        else:
            data = html.index
            content_type = 'text/html'

        self.send_response(200)
        self.send_header('Content-type', content_type)
        self.end_headers()
        self.wfile.write(data)


class ThreadingHTTPServer(SocketServer.ThreadingMixIn,
                          BaseHTTPServer.HTTPServer):
    pass


def stop_signal_handler(signum, frame):
    yubiserveHTTP.shutdown()
    sys.exit(0)


if __name__ == '__main__':
    parser = optparse.OptionParser('Usage: %prog [options]')
    parser.add_option('-d', '--db', default='./yubikeys.sqlite3', dest='db')
    parser.add_option('-a', '--address', default='0.0.0.0', dest='host')
    parser.add_option('-p', '--port', default='8000', dest='port')
    (options, args) = parser.parse_args()
    sqlite_db = options.db

    yubiserveHTTP = ThreadingHTTPServer((options.host, int(options.port)),
                                        YubiHTTPServer)

    signal.signal(signal.SIGINT, stop_signal_handler)

    http_thread = threading.Thread(target=yubiserveHTTP.serve_forever)
    http_thread.setDaemon(True)
    http_thread.start()
    print "Yubiserve running at {0}:{1}".format(options.host, options.port)

    signal.pause()
