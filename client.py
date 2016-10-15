#!/usr/bin/python3

import http.client
import urllib.request
import ssl
import json

class ServerClient:
	def __init__(self, conffile = "/etc/easiwids/client.conf"):
		self.config = None

		with open("client.conf") as f:
			try:
				self.config = json.loads(f.read())
			except Exception as e:
				print("Cannot load config: %s" % e)

		for param in ["server", "port", "key", "name"]:
			if param not in self.config:
				print("Error: '%s' parameter missing from client.conf" % param)
				exit()

	def report(self, name, mac): # returns tuple: (bool:SuccessfulConnect, bool:SuccessfulReport, bool:Verdict, str:Message)
		conn = http.client.HTTPSConnection(self.config["server"], self.config["port"], context = ssl._create_unverified_context())
		params = urllib.request.urlencode( [ ("key", self.config["key"]), ("name", name), ("mac", mac), ("client", self.config["name"]) ] )
		#params = urllib.request.urlencode({"key" : self.config["key"], "name" : name, "mac" : mac, "client" : self.config["name"]})
		conn.request("GET", "/api/v1/announce/?" + params)
		obj = None
		try:
			obj = json.loads(conn.getresponse().read())
			conn.close()
		except Exception as e:
			return (False, False, False, str(e))

		if "status" not in obj:
			return (False, False, False, "Unknown error!")

		if obj["status"] == "ERR":
			if "message" not in obj:
				return (True, False, False, "Unknown error!")
			if obj["message"] == "Unauthorized":
				return (True, False, False, "Server did not accept client key!")
			else:
				return (True, False, False, obj["message"])
		elif obj["status"] == "OK":
			pass
		else:
			return (True, False, False, "Server responded with unknown status!")

		message = "OK"
		if "message" in obj:
			message = obj["message"]

		return (True, True, obj["result"]["verdict"] == "TERMINATE", message)
