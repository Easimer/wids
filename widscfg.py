import json

arbitrary = False

with open("/etc/easiwids/client.conf") as f:
	try:
		c = json.loads(f.read())
		for k in c:
			globals()[k] = c[k]
	except Exception as e:
		print("[\033[93mwidscfg\033[0m] couldn't load configuration file: %s" % str(e))
		raise Exception()
	else:
		print("[\033[93mwidscfg\033[0m] configuration file loaded")
