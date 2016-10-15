import sqlite3
import threading
import signal
import os
import time

import widscfg
import iw
import cm

__apiversion__ = "v1"
__clversion__ = "1.0.0"

threads = []
interfaces = []
attacker_pool = []

def oninterrupt(signum, frame):
	print("KEYBOARD INTERRUPT RECEIVED")
	cm.cleanup()
	for interface in interfaces:
		interface.quit = True
	time.sleep(1.5) # wait for sniffings to stop
	for interface in interfaces:
		if not interface.monitor_off():
				print("\tFailed to remove monitor of %s" % interface.netif)

def netif_scan_thread(netif):
	print("[netif %s] thread start" % netif)
	iwif = iw.IW(netif)
	iwif.monitor_on()

	interfaces.append(iwif)
	
	timer = threading.Timer(0.250, netif_switchch, args=[iwif])
	timer.start()

	print("[netif %s] scanning has begun" % netif)
	iwif.scan()

	timer.cancel()

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

if __name__ == "__main__":

	print("EasiWIDS client (version: %s, API version: %s)" % (__clversion__, __apiversion__))

	if not hasattr(widscfg, "devices"):
		print("No devices are defined")
		exit()

	signal.signal(signal.SIGINT, oninterrupt)

	for dev in widscfg.devices:
		if "name" not in dev:
			continue
		name = dev["name"]
		offensive = False
		if "offensive" in dev:
			offensive = dev["offensive"]
		if offensive:
			cm.add_attacker(name)
		else:
			t = threading.Thread(target=netif_scan_thread, args=(dev["name"],))
			threads.append(t)
			t.start()

	for thread in threads:
		thread.join()
