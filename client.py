#!/usr/bin/python3

import http.client
import urllib.parse
import ssl
import json
import widscfg

class ServerClient:

	def report(self, name, mac): # returns tuple: (bool:SuccessfulConnect, bool:SuccessfulReport, bool:Verdict, str:Message)
		conn = http.client.HTTPSConnection(widscfg.server, widscfg.port, context = ssl._create_unverified_context())
		params = urllib.parse.urlencode( [ ("key", widscfg.key), ("name", name), ("mac", mac), ("client", widscfg.name) ] )
		try:
			conn.request("GET", "/api/v1/announce/?" + params)
		except Exception as e:
			return (False, False, False, str(e))
		obj = None
		try:
			obj = json.loads(conn.getresponse().read().decode('utf-8'))
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
