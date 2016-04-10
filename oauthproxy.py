#!/usr/bin/python3

import argparse
from oauth2client import client
from urllib import parse
import requests
from http import server
import socket


parser = argparse.ArgumentParser(description='oauthproxy')
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
FLAGS = parser.parse_args()


class HTTPServer6(server.HTTPServer):
  address_family = socket.AF_INET6


class OAuthProxy(object):

  def __init__(self, listen_host, listen_port, api_key):
    self._api_key = api_key

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

  def Serve(self):
    self._httpd.serve_forever()

  def _GetFlow(self, req):
    return_url = ''.join([
      'http://',
      req.headers['Host'],
      '/oauth2callback',
    ])
    return client.flow_from_clientsecrets(
        'client_secrets.json',
        scope='https://www.googleapis.com/auth/userinfo.email',
        redirect_uri=return_url)

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
    req.send_response(200)
    req.end_headers()
    req.wfile.write(emails[0].encode('utf8'))


def main():
  server = OAuthProxy(
      FLAGS.listen_host,
      FLAGS.listen_port,
      FLAGS.api_key)
  server.Serve()


if __name__ == '__main__':
  main()
