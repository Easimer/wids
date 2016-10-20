import sqlite3
import threading
import signal
import os
import time
import sys

import widscfg
import iwf
import tasks

__apiversion__ = "v1"
__clversion__ = "1.1.0"

threads = []
interfaces = []
attacker_pool = []

def oninterrupt(signum, frame):
	print("KEYBOARD INTERRUPT RECEIVED")
	for interface in interfaces:
		interface.quit = True
	time.sleep(1.5) # wait for sniffings to stop
	for interface in interfaces:
		if not interface.monitor_off():
				print("\tFailed to remove monitor of %s" % interface.netif)

def netif_init(netif, offensive):
	iwif = iw.IW(netif, iw.TYPE_ATTACK if offensive else iw.TYPE_RADAR)
	iwif.monitor_on()
	interfaces.append(iwif)
	print("[\033[93mnetif \033[91m%s\033[0m] activated" % netif)
	iwif.loop()

def netif_switchch(*args):
	iwobj = args[0]
	newch = (iwobj.channel + 1) % 12
	if newch == 0:
		newch = 1
	if not iwobj.set_channel(newch):
		iwobj.set_channel(1)
	if iwobj.quit:
		return
	threading.Timer(0.5, netif_switchch, args=args).start()

def parse_args():
	args = sys.argv[1:]
	for arg in args:
		if arg == "-a":
			print("arbitrary mode")
			widscfg.arbitrary = True

if __name__ == "__main__":

	print("EasiWIDS client (version: %s, API version: %s)" % (__clversion__, __apiversion__))

	parse_args()

	if not hasattr(widscfg, "devices"):
		print("No devices are defined")
		exit()

	signal.signal(signal.SIGINT, oninterrupt)

	# add ch 1-11 as tasks

	for channel in range(1, 12):
		tasks.task_add(tasks.Task(target=tuple([channel]), ttype=tasks.TYPE_WIRELESS_STARGET))

	for dev in widscfg.devices:
		if "name" not in dev:
			continue
		name = dev["name"]
		offensive = False
		if "offensive" in dev:
			offensive = dev["offensive"]
		t = threading.Thread(target=netif_init, args=(dev["name"],offensive))
		threads.append(t)
		t.start()

	for thread in threads:
		thread.join()
