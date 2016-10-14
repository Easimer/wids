#!/usr/bin/python2

### EasiWIDS Central Server

"""
You have to provide certificate files for the server. One way is to get one from a
certificate authority and place them in the keys/ dictionary:
- keys/key.pem should be the key
- keys/cert.pem should be the certificate
The other way is to generate a self-signed cert. using OpenSSL:

$ openssl req -x509 -newkey rsa:4096 -keyout keys/key.pem -out keys/cert.pem -days 365

You may want to strip the PEM password from the key:

$ openssl rsa -in keys/key.pem -out keys/key.pem

The next step is to create some API keys/client keys. The clients will authenticate themselves
using this key. It's recommended to use the add_key.py script included with this code.

$ python2 add_key.py <NAME>

This generates a 64 characters long random string including lowercase, uppercase and numerical
characters and adds it to the database, along with a name to remind you who/what that
key belongs to.

Now you should add some authorized access points to the server's database. Run the
add_ap.py script:
$ python2 add_ap.py <SSID> <MAC ADDRESS>

The final step is to set up some clients.
"""

import BaseHTTPServer, SimpleHTTPServer
import ssl
import json
from urlparse import urlparse
import sqlite3
import urllib

__apiversion__ = "v1"

dbcur = None

# authenticates client key
def auth_key(key):
	if not dbcur:
		return False # cannot authenticate
	rows = [row for row in dbcur.execute("SELECT name FROM apikeys WHERE key=?", [key])]
	return len(rows) != 0

def auth_ap(name, mac):
	if not dbcur:
		return False
	rows = [row for row in dbcur.execute("SELECT * FROM authorized WHERE name=? AND mac=?", (name, mac))]
	return len(rows) != 0


class EasiWIDSHTTPHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):

	server_version = "EasiWIDS " + __apiversion__

	def do_GET(self):
		url = urlparse(self.path)
		path = [elem for elem in url.path.split('/') if elem != '']
		if len(path) < 3 or path[0] != 'api':
			self.send_response(404)
			self.send_header('Content-Type', 'application/json')
			self.end_headers()
			response = {
				"status" : "ERR",
				"message" : "Not Found"
			}
			self.wfile.write(json.dumps(response))
			return

		if path[1] != __apiversion__:
			self.send_response(501)
			self.send_header('Content-Type', 'application/json')
			self.end_headers()
			response = {
				"status" : "ERR",
				"message" : "Not Implemented"
			}

			self.wfile.write(json.dumps(response))
			return

		
		query = urllib.unquote(url.query)
		query = [elem.split('=') for elem in query.split('&')]

		queryd = {}
		for elem in query:
			if len(elem) == 2:
				queryd[elem[0]] = elem[1]
			elif len(elem) == 1:
				queryd[elem[0]] = None

		if path[2] == "announce":
			self.announce(queryd)
		return

	def announce(self, query):
		# Retrieve and check the API key
		key = None
		if not ("key" in query and query["key"]):
			self.send_response(400)
			self.send_header('Content-Type', 'application/json')
			self.end_headers()
			response = {
				"status" : "ERR",
				"message" : "No client key"
			}
			self.wfile.write(json.dumps(response))
			return
		
		key = query["key"]

		if not auth_key(key):
			self.send_response(403)
			self.send_header('Content-Type', 'application/json')
			self.end_headers()
			response = {
				"status" : "ERR",
				"message" : "Unauthorized"
			}
			self.wfile.write(json.dumps(response))
			return
		
		# Retrieve the SSID
		if not ("name" in query and query["name"]):
			self.send_response(400)
			self.send_header('Content-Type', 'application/json')
			self.end_headers()
			response = {
				"status" : "ERR",
				"message" : "Parameter is missing",
				"parameter" : "name"
			}
			self.wfile.write(json.dumps(response))
			return
		ssid = query["name"]

		# Retrieve MAC address
		if not ("mac" in query and query["mac"]):
			self.send_response(400)
			self.send_header('Content-Type', 'application/json')
			self.end_headers()
			response = {
				"status" : "ERR",
				"message" : "Parameter is missing",
				"parameter" : "mac"
			}
			self.wfile.write(json.dumps(response))
			return

		mac = query["mac"]

		response = {
			"status" : "OK",
			"result" : {
				"name" : ssid,
				"mac" : mac,
				"verdict" : "OK"
			}
		}

		self.send_response(200)
		self.send_header('Content-Type', 'application/json')
		self.end_headers()

		if not auth_ap(ssid, mac):
			response["result"]["verdict"] = "TERMINATE"
		
		self.wfile.write(json.dumps(response))
		# TODO: log report

httpd = BaseHTTPServer.HTTPServer(('0.0.0.0', 8080), EasiWIDSHTTPHandler)

dbconn = sqlite3.connect('server.db')
dbcur = dbconn.cursor()

dbcur.execute("CREATE TABLE IF NOT EXISTS apikeys(name varchar, key varchar)")
dbcur.execute("CREATE TABLE IF NOT EXISTS authorized(name varchar, mac varchar)")

httpd.socket = ssl.wrap_socket(httpd.socket, keyfile='keys/key.pem', certfile='keys/cert.pem', server_side = True, )

httpd.serve_forever()
