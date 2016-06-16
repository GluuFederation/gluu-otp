import time
import urlparse
import BaseHTTPServer

from gluuotp.validate import Yubico

HOST = '0.0.0.0'
PORT = 8010


class GluuOTPHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    def do_HEAD(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()

    def do_GET(self):
        # TODO
        # 1. get the query params
        url_parts = urlparse.urlparse(self.path)
        params = urlparse.parse_qs(url_parts.query)
        # 2. make sure there is an item called otp
        if 'otp' not in params:
            self.send_response(400)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            self.wfile.write("OTP Not found in request.")
        # 3. validate the otp
        validator = Yubico('LDAP')
        result = validator.validate(params['otp'][0])

        # 4. reply with the status of validation
        self.send_response(200)
        self.send_header("Content-type", "text/plain")
        self.end_headers()
        self.wfile.write(result)


if __name__ == '__main__':
    server_class = BaseHTTPServer.HTTPServer
    httpd = server_class((HOST, PORT), GluuOTPHandler)
    print time.asctime(), "Server Starts - %s:%s" % (HOST, PORT)

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print time.asctime(), "Server Stops - %s:%s" % (HOST, PORT)

    httpd.server_close()
