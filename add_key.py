#!/usr/bin/python2

import sqlite3
import random
import string
import sys

if len(sys.argv) < 2:
	print("Usage: %s name" % sys.argv[0])
	exit()

dbconn = sqlite3.connect('server.db')
dbcur = dbconn.cursor()

dbcur.execute("CREATE TABLE IF NOT EXISTS apikeys(name varchar, key varchar)")

name = sys.argv[1]
key = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits + string.ascii_lowercase) for _ in range(64))

dbcur.execute("INSERT INTO apikeys VALUES(?, ?)", (name, key))
dbconn.commit()
dbconn.close()
