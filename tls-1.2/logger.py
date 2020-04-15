import sys, time

class logger:
	def __init__(self, logFile):
		self.logFile = logFile
		self.logfd = None
		self.read_error = 0
		try:
			self.logfd = open(self.logFile, 'w+')
		except:
			self.read_error = 1

	def tostdout(self, msg, crit="INFO"):
		self.msg = "\n%s -> %s: %s\n" % ( str(time.asctime()), crit, msg)

		sys.stdout.write(self.msg)

	def tofile(self, msg, crit="INFO"):
		self.msg = "\n%s -> %s: %s\n" % ( str(time.asctime()), crit, msg)
		
		self.logfd.write(self.msg)

	def toboth(self, msg, crit="INFO"):
		self.msg = "\n%s -> %s: %s\n" % ( str(time.asctime()), crit, msg)

		sys.stdout.write(self.msg)		

		self.logfd.write(self.msg)
	
	def close(self):
		self.logfd.close()

