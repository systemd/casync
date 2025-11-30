#!/usr/bin/python3
# SPDX-License-Identifier: LGPL-2.1+
import argparse
import ssl
import uuid
from datetime import datetime, timedelta
from os.path import exists, abspath

from cryptography import x509
from cryptography.hazmat._oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import ExtensionType

DEFAULT_PORT = 4321

import http.server
import os
import socket
import socketserver

CERT_VALIDITY = timedelta(31, 0, 0)


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


def create_cert(subject_name, issuer_name, extval: ExtensionType, critical: bool, ca_key=None):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject_name)
    builder = builder.issuer_name(issuer_name)
    builder = builder.not_valid_before(datetime.today() - CERT_VALIDITY)
    builder = builder.not_valid_after(datetime.today() + CERT_VALIDITY)
    builder = builder.serial_number(int(uuid.uuid4()))
    builder = builder.public_key(private_key.public_key())
    builder = builder.add_extension(extval, critical)
    return builder.sign(private_key=ca_key if ca_key else private_key, algorithm=hashes.SHA256(),
                        backend=default_backend()), private_key


def create_certs(HostName, KeyFile, CertFile, ClientCertCAs):
    ca_subject_name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "CA_TEST"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'TEST ON'),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u'TEST OUN'),
    ])

    ca_cert, ca_key = create_cert(ca_subject_name, ca_subject_name, x509.BasicConstraints(ca=True, path_length=None),
                                  critical=False)

    server_cert, server_key = create_cert(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, HostName),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'TEST ON'),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u'TEST OUN'),
    ]), ca_subject_name, x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.SERVER_AUTH]), False, ca_key)

    client_cert, client_key = create_cert(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, HostName),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'TEST ON'),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u'TEST OUN'),
    ]), ca_subject_name, x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.CLIENT_AUTH]), False, ca_key)

    open(KeyFile, "wb").write(server_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ))
    open(CertFile, "wb").write(server_cert.public_bytes(
        encoding=serialization.Encoding.PEM,
    ))
    open("client.key", "wb").write(client_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                            format=serialization.PrivateFormat.TraditionalOpenSSL,
                                                            encryption_algorithm=serialization.NoEncryption()))
    open("client.crt", "wb").write(client_cert.public_bytes(
        encoding=serialization.Encoding.PEM,
    ))
    open(ClientCertCAs, "wb").write(ca_cert.public_bytes(encoding=serialization.Encoding.PEM))


def run_server(https: bool, host_name, port, key_file=None, cert_file=None, client_cert_ca=None):
    httpd = AllowReuseAddressServer((host_name, port), http.server.SimpleHTTPRequestHandler)

    if https:
        if not exists(key_file) or not exists(cert_file) or not exists(client_cert_ca):
            print("Generating Key and Certificate...")
            create_certs(host_name, key_file, cert_file, client_cert_ca)
        print("mtls server")
        httpd.socket = ssl.wrap_socket(httpd.socket, keyfile=key_file, certfile=cert_file, server_side=True,
                                       cert_reqs=ssl.CERT_REQUIRED, ca_certs=client_cert_ca,
                                       ssl_version=ssl.PROTOCOL_TLSv1_2)
        protocol = 'HTTPS'
        print("    Cert:", abspath(cert_file))

    else:
        protocol = 'HTTP'

    sa = httpd.socket.getsockname()
    print("Serving", protocol, "on", sa[0], "port", sa[1], "...")
    httpd.serve_forever()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--ssl', action='store_true', dest='SSL',
                        help='Launches an SSL (HTTPS) server (default: False)', default=False)
    parser.add_argument('--host', action='store', dest='HostName', default="localhost",
                        help='Sets the host name to listen on (default: localhost)')
    parser.add_argument('--port', action='store', dest='Port', type=int, default=DEFAULT_PORT,
                        help='Sets the port to listen on (default for HTTPS)')
    parser.add_argument('--key', action='store', dest='KeyFile', default="server.key",
                        help='Sets the private key to use for SSL.')
    parser.add_argument('--cert', action='store', dest='CertFile', default="server.crt",
                        help='''Sets the public certificate to use for SSL.  Implies --ssl 
                                  (default: Temp-generated certificate*)''')
    parser.add_argument('--certbase', action='store', dest='CertBase',
                        help='Sets the base path to a certificate and key (default: None*)')
    parser.add_argument('--cacert', action='store', dest='ClientCertCAs', default="ca.crt",
                        help='Sets the CA to use for authenticating client certs.')
    parser.add_argument('workdir', action='store', help='workdir')

    args = parser.parse_args()
    os.chdir(args.workdir)

    run_server(args.SSL, args.HostName, args.Port, args.KeyFile, args.CertFile, args.ClientCertCAs)
