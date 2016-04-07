#!/usr/bin/python3

import argparse
import requests
import sys


parser = argparse.ArgumentParser(description='certclient')
parser.add_argument(
    '--ca-cert',
    dest='ca_cert',
    action='store',
    required=True)
parser.add_argument(
    '--client-cert',
    dest='client_cert',
    action='store',
    required=True)
parser.add_argument(
    '--client-key',
    dest='client_key',
    action='store',
    required=True)
parser.add_argument(
    '--server',
    dest='server',
    action='store',
    required=True)
FLAGS = parser.parse_args()


class CertClient(object):

  def __init__(self, server, ca_cert, client_cert, client_key):
    self._session = requests.Session()
    self._session.verify = ca_cert
    self._session.cert = (client_cert, client_key)
    self._session.headers.update({
      'Content-Type': 'application/x-pem-file',
    })
    self._server = server

  def Request(self, csr):
    resp = self._session.post(self._server, data=csr)
    assert resp.status_code == requests.codes.ok, resp.status_code
    assert resp.headers['Content-Type'] == 'application/x-pem-file', resp.headers['Content-Type']
    return resp.text


def main():
  client = CertClient(
      FLAGS.server,
      FLAGS.ca_cert,
      FLAGS.client_cert,
      FLAGS.client_key)
  cert = client.Request(sys.stdin.read())
  print(cert, end='')


if __name__ == '__main__':
  main()
