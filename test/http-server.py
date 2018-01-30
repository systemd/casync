#!/usr/bin/python3
# SPDX-License-Identifier: LGPL-2.1+

PORT = 4321

import http.server
import os
import socket
import socketserver
import sys
import time
os.chdir(sys.argv[1])

if len(sys.argv) >= 3:
    PORT = int(sys.argv[2])

def send_notify(text):

    if text is None or text == "":
        return

    e = os.getenv("NOTIFY_SOCKET")
    if e is None:
        return

    assert len(e) >= 2
    assert e[0] == '/' or e[0] == '@'

    fd = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    fd.connect("\0" + e[1:] if e[0] == '@' else e)
    fd.send(bytes(text, 'utf-8'))

class AllowReuseAddressServer(socketserver.TCPServer):
    allow_reuse_address = True

    def server_activate(self):
        super().server_activate()
        send_notify("READY=1")

httpd = AllowReuseAddressServer(("", PORT), http.server.SimpleHTTPRequestHandler)

httpd.serve_forever()
