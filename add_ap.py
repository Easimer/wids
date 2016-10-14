#!/usr/bin/python2

import sqlite3
import sys

if len(sys.argv) < 3:
	print("Usage: %s ssid mac" % sys.argv[0])
	exit()

dbconn = sqlite3.connect('server.db')
dbcur = dbconn.cursor()

dbcur.execute("CREATE TABLE IF NOT EXISTS authorized(name varchar, key varchar)")

name = sys.argv[1]
mac = sys.argv[2]

dbcur.execute("INSERT INTO authorized VALUES(?, ?)", (name, mac))
dbconn.commit()
dbconn.close()
