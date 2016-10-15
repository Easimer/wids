#!/usr/bin/python2

### EasiWIDS Central Server

"""
You have to provide certificate files for the server. One way is to get one from a
certificate authority and place them in the keys/ dictionary:
- keys/key.pem should be the key
- keys/cert.pem should be the certificate
The other way is to generate a self-signed cert. using OpenSSL:

# openssl req -x509 -newkey rsa:4096 -keyout /etc/easiwids/keys/key.pem -out /etc/easiwids/keys/cert.pem -days 365

You may want to strip the PEM password from the key:

# openssl rsa -in /etc/easiwids/keys/key.pem -out /etc/easiwids/keys/key.pem

Also, make the PEM files readable only by the 'root' user:
# chown -R root:root /etc/easiwids/keys/
# chmod -R 600 /etc/easiwids/keys/

The next step is to create some API keys/client keys. The clients will authenticate themselves
using this key. It's recommended to use the 'addkey' mode of the server.

# python2 server.py addkey <NAME>

This generates a 64 characters long random string including lowercase, uppercase and numerical
characters and adds it to the database, along with a name to remind you who/what that
key belongs to.

Now you should add some authorized access points to the server's database. Run the
server with mode 'addap':
# python2 server.py addap <SSID> <MAC ADDRESS>

The final step is to set up some clients.
"""

import BaseHTTPServer, SimpleHTTPServer
import ssl
import json
from urlparse import urlparse
import sqlite3
import urllib
import sys
import random
import string

__apiversion__ = "v1"
__srvversion__ = "1.0.0"

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

if __name__ == "__main__":

	print("EasiWIDS central server (version: %s, API version: %s)" % (__srvversion__, __apiversion__))

	if len(sys.argv) > 1:
		mode = sys.argv[1]
		if mode == "addkey":
			if len(sys.argv) < 3:
				print("Usage: %s addkey name" % sys.argv[0])
				exit()
			dbconn = sqlite3.connect('/etc/easiwids/server.db')
			dbcur = dbconn.cursor()

			dbcur.execute("CREATE TABLE IF NOT EXISTS apikeys(name varchar, key varchar)")

			name = sys.argv[1]
			key = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits + string.ascii_lowercase) for _ in range(64))

			dbcur.execute("INSERT INTO apikeys VALUES(?, ?)", (name, key))
			dbconn.commit()
			dbconn.close()
			print("New key created and stored:\n\tName:\t%s\n\tKey:\t%s" % (name, key))
			exit()
		elif mode == "revokekey":
			if len(sys.argv) < 3:
				print("Usage: %s revokekey name" % sys.argv[0])
				exit()
			dbconn = sqlite3.connect('/etc/easiwids/server.db')
			dbcur = dbconn.cursor()

			dbcur.execute("CREATE TABLE IF NOT EXISTS apikeys(name varchar, key varchar)")

			name = sys.argv[1]

			dbcur.execute("DELETE FROM apikeys WHERE name=?", (name,))
			dbconn.commit()
			dbconn.close()
		elif mode == "addap":
			if len(sys.argv) < 4:
				print("Usage: %s addap ssid mac" % sys.argv[0])
				exit()
			dbconn = sqlite3.connect('/etc/easiwids/server.db')
			dbcur = dbconn.cursor()

			dbcur.execute("CREATE TABLE IF NOT EXISTS authorized(name varchar, key varchar)")

			name = sys.argv[1]
			mac = sys.argv[2]

			dbcur.execute("INSERT INTO authorized VALUES(?, ?)", (name, mac))
			dbconn.commit()
			dbconn.close()
			print("New authorized AP added:\n\tSSID:\t%s\nMAC:\t%s" % (name, mac))
			exit()
		elif mode == "removeap":
			if len(sys.argv) < 4:
				print("Usage: %s removeap ssid mac" % sys.argv[0])
				exit()
			dbconn = sqlite3.connect('/etc/easiwids/server.db')
			dbcur = dbconn.cursor()

			dbcur.execute("CREATE TABLE IF NOT EXISTS authorized(name varchar, key varchar)")

			name = sys.argv[1]
			mac = sys.argv[2]

			dbcur.execute("DELETE FROM authorized WHERE name=? AND mac=?", (name, mac))
			dbconn.commit()
			dbconn.close()
			print("AP removed:\n\tSSID:\t%s\nMAC:\t%s" % (name, mac))
			exit()
		elif mode == "listap":
			dbconn = sqlite3.connect('/etc/easiwids/server.db')
			dbcur = dbconn.cursor()
			print("SSID - MAC\n==========")
			for ap in dbcur.execute("SELECT * FROM authorized;"):
				print("%s - %s" % (ap[0], ap[1]))
			dbconn.close()
			exit()
		elif mode == "listkey":
			dbconn = sqlite3.connect('/etc/easiwids/server.db')
			dbcur = dbconn.cursor()
			print("ID - Key\n==========")
			for key in dbcur.execute("SELECT * FROM apikeys;"):
				print("%s - %s" % (key[0], key[1]))
			dbconn.close()
			exit()
		else:
			print("Usage: %s [mode] [mode args]" % sys.argv[0])
			print("If there is a mode provided, the WIDS server will not run.")
			print("\tModes:")
			print("\t\taddap - adds an authorized Access Point to the database")
			print("\t\tremoveap - remove an authorized Access Point from the database")
			print("\t\tlistap - list authorized Access Points")
			print("\t\taddkey - adds a client key to the database")
			print("\t\trevokekey - revokes a client key")
			print("\t\tlistkey - list client keys")
			exit()

	httpd = BaseHTTPServer.HTTPServer(('0.0.0.0', 8080), EasiWIDSHTTPHandler)

	dbconn = sqlite3.connect('/etc/easiwids/server.db')
	dbcur = dbconn.cursor()

	dbcur.execute("CREATE TABLE IF NOT EXISTS apikeys(name varchar, key varchar)")
	dbcur.execute("CREATE TABLE IF NOT EXISTS authorized(name varchar, mac varchar)")

	httpd.socket = ssl.wrap_socket(httpd.socket, keyfile='/etc/easiwids/keys/key.pem', certfile='/etc/easiwids/keys/cert.pem', server_side = True, )

	httpd.serve_forever()
