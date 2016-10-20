TYPE_WIRELESS_STARGET = 0 # scan target target=(channel)
TYPE_WIRELESS_ATARGET = 1 # attack target target=(ssid, channel, mac)
TYPE_DHCP_ATARGET = 3 #  dhcp attack target target=(server_id)

class Task:
	def __init__(self, target, ttype):
		self.target = target
		self.lock = False
		self.type = ttype

	def acquire(self):
		if self.lock:
			return True
		else:
			#print("[\033[93mtasks\033[0m] task for target '%s' acquired" % str(self.target))
			self.lock = True
			return False

	def unlock(self):
		#print("[\033[93mtasks\033[0m] task for target '%s' unlocked" % str(self.target))
		self.lock = False

tasks = []

def task_add(task):
	global tasks
	tasks.append(task)