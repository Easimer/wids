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
import time

__apiversion__ = "v1"
__srvversion__ = "1.0.0"

dbcur = None
reports = []
clients = []

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

		
		query = urllib.unquote_plus(url.query)
		query = [elem.split('=') for elem in query.split('&')]

		queryd = {}
		for elem in query:
			if len(elem) == 2:
				queryd[elem[0]] = elem[1]
			elif len(elem) == 1:
				queryd[elem[0]] = None

		if path[2] == "announce":
			self.announce(queryd)
		elif path[2] == "login":
			self.login(queryd)
		elif path[2] == "status":
			self.status(queryd)
		else:
			self.send_response(404)
			self.send_header('Content-Type', 'application/json')
			self.end_headers()
			response = {
				"status" : "ERR",
				"message" : "Not Found"
			}

			self.wfile.write(json.dumps(response))
			return

	def missing_param(self, param):
		self.send_response(400)
		self.send_header('Content-Type', 'application/json')
		self.end_headers()
		response = {
			"status" : "ERR",
			"message" : "Parameter is missing",
			"parameter" : param
		}
		self.wfile.write(json.dumps(response))

	def announce(self, query):
		# Retrieve and check the API key
		key = None
		if not ("key" in query and query["key"]):
			self.missing_param("key")
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
			self.missing_param("name")
			return
		ssid = query["name"]

		# Retrieve MAC address
		if not ("mac" in query and query["mac"]):
			self.missing_param("mac")
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

		client = "(unknown)"

		if "client" in query:
			if query["client"]:
				client = query["client"]
			found = False
			for client in clients:
				if client[0] == query["client"]:
					found = True
			if not found:
				response["login"] = "REQUIRED"

		self.send_response(200)
		self.send_header('Content-Type', 'application/json')
		self.end_headers()

		authorized = auth_ap(ssid, mac)

		if not authorized:
			response["result"]["verdict"] = "TERMINATE"
		
		self.wfile.write(json.dumps(response))
		
		found = False
		for report in reports:
			if report[0] == ssid and report[1] == mac:
				report[3] = time.time()
				found = True
				break
		if not found:
			t = [ssid, mac, authorized, time.time(), client]
			reports.append(t)

	def login(self, query):
		key = None
		if not ("key" in query and query["key"]):
			self.missing_param("key")
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

		if not ("name" in query and query["name"]):
			self.missing_param("name")
			return
		if not ("iw" in query and query["iw"]):
			self.missing_param("iw")
			return

		name = query["name"]
		iw = query["iw"].split(' ')
		found = False
		for client in clients:
			if client[0] == name:
				found = True
				break
		if not found:
			t = (name, iw)
			clients.append(t)

		response = {
			"status" : "OK",
		}

		self.send_response(200)
		self.send_header('Content-Type', 'application/json')
		self.end_headers()
		self.wfile.write(json.dumps(response))

	def status(self, query):
		key = None
		if not ("key" in query and query["key"]):
			self.missing_param("key")
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

		status_head_template = "<DOCTYPE !html><html lang='en'><head><meta charset='utf-8'><title>EasiWIDS</title></head>"
		status_body1_template = "<body><h2>EasiWIDS Status</h2><div><h3>Detected APs</h3><ul>"
		status_body2_template = "</ul></div><div><h3>Clients</h3><ul>"
		status_tail_template = "</ul></body></html>"
		status_ap_template = "<li>__CLIENT__: <span style='color: __COLOR__'>__SSID__ (__MAC__)</span></li>"
		status_cl_template = "<li>__NAME__: __IWLIST__</li>"

		self.send_response(200)
		self.send_header('Content-Type', 'text/html')
		self.end_headers()

		self.wfile.write(status_head_template)
		self.wfile.write(status_body1_template)
		for report in reports:
			self.wfile.write(status_ap_template.replace("__COLOR__", "red" if not report[2] else "black").replace("__SSID__", report[0]).replace("__MAC__", report[1]).replace("__CLIENT__", report[4]))
		self.wfile.write(status_body2_template)
		for client in clients:
			self.wfile.write(status_cl_template.replace("__NAME__", client[0]).replace("__IWLIST__", ', '.join(client[1])))
		self.wfile.write(status_tail_template)


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
