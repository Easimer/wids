import subprocess
import pcap
import dpkt
import os

class IW:
	def __init__(self, netif, authorized):
		if not netif:
			return
		self.netif = netif
		self.authorized = authorized
		self.detected = []
		self.channel = 1
		self.quit = False
		self.DEVNULL = open(os.devnull, 'w')
		if subprocess.call(["airmon-ng", "start", netif], stdout=self.DEVNULL, stderr=self.DEVNULL) != 0:
			print("[netif %s] cannot set monitor mode" % (self.netif))
			self.quit = True
			return
		else:
			self.netif += "mon"

		self.set_channel(1)

	def set_channel(self, channel):
		if subprocess.call(["iw", "dev", self.netif, "set", "channel", str(channel)], stdout=self.DEVNULL, stderr=self.DEVNULL) != 0:
			print("[netif %s] cannot set channel to %d" % (self.netif, channel))
			return False
		self.channel = channel
		print("[netif %s] set channel to %d" % (self.netif, channel))
		return True
			

	def loop(self):
		try:
			pc = pcap.pcap(self.netif)
			counter = 0
			for timestamp, packet in pc:
				if self.quit:
					break
				parsed = dpkt.radiotap.Radiotap(packet).data
				if parsed.type == 0 and parsed.subtype == 8:
					src = ":".join("{:02x}".format(ord(c)) for c in parsed.mgmt.src)
					t = (parsed.ssid.info, src)
					if t not in self.authorized:
						if t not in self.detected:
							self.authorized.append(t)
							print("Unauthorized AP detected: " + str(t))
		except:
			print("[netif %s] interrupted, quitting" % self.netif)
			self.quit = True
			self.close()
			return
			
	def close(self):
		if subprocess.call(["airmon-ng", "stop", self.netif], stdout=self.DEVNULL, stderr=self.DEVNULL) != 0:
			print("[netif %s] cannot deactivate monitor mode" % self.netif)