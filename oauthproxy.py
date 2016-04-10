#!/usr/bin/python3

import argparse
from oauth2client import client
import os
from urllib import parse
import requests
from http import server
import socket
import ssl
import subprocess
import tempfile


parser = argparse.ArgumentParser(description='oauthproxy')
parser.add_argument(
    '--allowed-domain',
    dest='allowed_domain',
    action='store',
    required=True)
parser.add_argument(
    '--api-key',
    dest='api_key',
    action='store',
    required=True)
parser.add_argument(
    '--listen-host',
    dest='listen_host',
    action='store',
    default='::')
parser.add_argument(
    '--listen-port',
    dest='listen_port',
    type=int,
    action='store',
    default=443)
parser.add_argument(
    '--server-key',
    dest='server_key',
    action='store',
    required=True)
parser.add_argument(
    '--server-cert',
    dest='server_cert',
    action='store',
    required=True)
parser.add_argument(
    '--subject',
    dest='subject',
    action='store',
    required=True)
FLAGS = parser.parse_args()


class HTTPServer6(server.HTTPServer):
  address_family = socket.AF_INET6


class OAuthProxy(object):

  def __init__(self, listen_host, listen_port, server_key, server_cert, api_key, allowed_domain, subject):
    self._api_key = api_key
    self._allowed_domain = allowed_domain
    self._subject = subject

    HANDLERS = {
      '/': self._ServeRedirect,
      '/oauth2callback': self._OAuth2Callback,
    }

    class RequestHandler(server.BaseHTTPRequestHandler):
      def do_GET(self):
        self.parsed_url = parse.urlparse(self.path)
        try:
          HANDLERS[self.parsed_url.path](self)
        except KeyError:
          self.send_response(404)
          self.end_headers()

    self._httpd = HTTPServer6((listen_host, listen_port), RequestHandler)
    self._httpd.socket = ssl.wrap_socket(
        self._httpd.socket,
        keyfile=server_key,
        certfile=server_cert,
        server_side=True)
    self._httpd.socket.settimeout(5.0)

  def Serve(self):
    self._httpd.serve_forever()

  def _GetFlow(self, req):
    return_url = ''.join([
      'https://',
      req.headers['Host'],
      '/oauth2callback',
    ])
    return client.flow_from_clientsecrets(
        'client_secrets.json',
        login_hint=self._allowed_domain,
        scope='https://www.googleapis.com/auth/userinfo.email',
        redirect_uri=return_url)

  def _GetCert(self, email):
    with tempfile.TemporaryDirectory() as td:
      key_path = os.path.join(td, 'key.pem')
      subprocess.check_call([
        'openssl', 'ecparam', '-genkey',
        '-name', 'secp384r1',
        '-out', key_path,
      ])
      csr_path = os.path.join(td, 'csr.pem')
      subprocess.check_call([
        'openssl', 'req', '-new',
        '-key', key_path,
        '-out', csr_path,
        '-subj', self._subject.replace('EMAIL', email),
      ])
      return open(csr_path, 'rb').read()

  def _ServeRedirect(self, req):
    req.send_response(302)
    req.send_header('Location', self._GetFlow(req).step1_get_authorize_url())
    req.end_headers()

  def _OAuth2Callback(self, req):
    qs = parse.parse_qs(req.parsed_url.query)
    credentials = self._GetFlow(req).step2_exchange(qs['code'][0])
    result = requests.get(
        'https://www.googleapis.com/plus/v1/people/me?%s' % parse.urlencode({
          'key': self._api_key,
          'access_token': credentials.access_token,
        }))
    emails = [
      x['value']
      for x in result.json()['emails']
      if x['type'] == 'account'
    ]
    email = emails[0]
    assert email.endswith('@%s' % self._allowed_domain)
    result = self._GetCert(email)
    req.send_response(200)
    req.end_headers()
    req.wfile.write(result)


def main():
  server = OAuthProxy(
      FLAGS.listen_host,
      FLAGS.listen_port,
      FLAGS.server_key,
      FLAGS.server_cert,
      FLAGS.api_key,
      FLAGS.allowed_domain,
      FLAGS.subject)
  server.Serve()


if __name__ == '__main__':
  main()
