#!/usr/bin/python3

PORT = 4321

import http.server, socketserver, os, sys

os.chdir(sys.argv[1])

class AllowReuseAddressServer(socketserver.TCPServer):
    allow_reuse_address = True

httpd = AllowReuseAddressServer(("", PORT), http.server.SimpleHTTPRequestHandler)
httpd.serve_forever()
