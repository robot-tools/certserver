#!/usr/bin/python3

from http import server
import socket
import ssl


class HTTPServer6(server.HTTPServer):
  address_family = socket.AF_INET6

httpd = HTTPServer6(('', 4443), server.SimpleHTTPRequestHandler)
httpd.socket = ssl.wrap_socket(
    httpd.socket,
    keyfile='/home/flamingcow/ca/client/private/test1.key.pem',
    certfile='/home/flamingcow/ca/client/certs/test1.cert.pem',
    server_side=True,
    cert_reqs=ssl.CERT_REQUIRED,
    ssl_version=ssl.PROTOCOL_TLSv1_2,
    ciphers='ECDHE-ECDSA-AES256-GCM-SHA384')
httpd.serve_forever()
