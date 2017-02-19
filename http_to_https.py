import sys, os, socket
from socketserver import ThreadingMixIn
from http.server import BaseHTTPRequestHandler, HTTPServer
from loader import httpsload

HOST = socket.gethostname()


class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        page = bytes(httpsload, 'utf-8')
        self.wfile.write(page)


class ThreadingRefferServer(ThreadingMixIn, HTTPServer):
    pass

'''
This sets the listening port, default port 8080
'''
if sys.argv[1:]:
    PORT = int(sys.argv[1])
else:
    PORT = 8080

'''
This sets the working directory of the HTTPServer, defaults to directory where script is executed.
'''
if sys.argv[2:]:
    os.chdir(sys.argv[2])
    CWD = sys.argv[2]
else:
    CWD = os.getcwd()

server = ThreadingRefferServer(('0.0.0.0', PORT), handler)
try:
    while 1:
        sys.stdout.flush()
        server.handle_request()
except KeyboardInterrupt:
    print("\nShutting down server per users request.")