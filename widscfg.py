import json

with open("/etc/easiwids/client.conf") as f:
	try:
		c = json.loads(f.read())
		for k in c:
			globals()[k] = c[k]
	except Exception as e:
		print("Couldn't load configuration file: %s" % str(e))
	else:
		print("Configuration file loaded")
