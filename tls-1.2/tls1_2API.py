#!/usr/bin/python

import os, sys, socket, string, struct, base64, hashlib, copy, random, hmac, math
sys.path.insert(0, "../")
from struct import *
from s_functions import *
from constants import *
import tlslite
from tlslite.api import *
from Crypto.Cipher import AES
from array import *
from hashlib import *

global enc_hs_with_reneg
global enc_hs_no_reneg
global enc_rec
global dec_rec
global dec_hs

###############################################################################
#
# Handshake Messages (after removing Record Layer Header till CKEMessage) are:
#
# 					self.sslStruct['cHello']
#					self.sslStruct['sHello']
#					self.sslStruct['sCertificate']
#					self.sslStruct['sHelloDone']
#					self.sslStruct['ckeMessage']
#
###############################################################################


class lib_tls:
	#
	# Constructor
	#
	def __init__(self, host, port, logger, cipher = "AES-128-SHA", debugFlag = 0):
		self.sslStruct = {}
		self.clientHello = None
		self.debugFlag = debugFlag
		self.socket = None
		self.logger = logger
		self.host = host
		self.port = port
		self.sslHandshake = None
		self.sslRecord = None
		self.opn = 0
		self.cipher = cipher
		self.decryptedData = ""

###############################################################################
#
# tcp_connect --
#
# 			Establishes a TCP connection and returns
#			the socket descriptor
#
# Results:
#			Establishes a TCP connection to a server:port
#			and returns socket
#
# Side Effects:
#			None
###############################################################################
	def tcp_connect(self):
		self.socket = socket.socket(socket.AF_INET,
					socket.SOCK_STREAM)
		self.socket.connect((self.host, self.port))


###############################################################################
#
# create_client_hello --
#
# 			Function to create a SSL Client Hello packet
#
# Results:
#			1. Creates a customized SSL Client Hello packet
#
# Side Effects:
#			None
###############################################################################
	def create_client_hello(self):
		if self.sslRecord == None:
			self.sslRecord = ""
		if self.sslHandshake == None:
			self.sslHandshake = ""

		self.sslHandshake = ""
		#
		# Handshake type is 1 (client hello)
		#
		self.sslHandshake += pack("B", 1)

		#
		# Handshake length is 41 (hexadecimal 0x29)
		#
		self.sslHandshake += "\x00\x00\x29"

		#
		# Handshake version is 771 (hexadecimal 0x0303)
		#
		self.sslHandshake += pack(">H", 771)

		#
		# Client Hello Random bytes
		#
		self.sslHandshake += DEFAULT_CH_CLIENT_RANDOM

		#
		# Session ID length is 0
		#
		self.sslHandshake += pack("B", 0)

		#
		# Cipher Suites length is 2 bytes
		#
		self.sslHandshake += pack(">H", 2)

		#
		# Cipher suite defined is AES-128-SHA
		#
		if self.cipher == "TLS_RSA_WITH_AES_128_CBC_SHA":
			self.sslHandshake += "\x00\x2F"
		elif self.cipher == "TLS_RSA_WITH_AES_256_CBC_SHA":
			self.sslHandshake += "\x00\x35"

		#
		# Compression methods length is 1 and compression method is 0 (none)
		#
		self.sslHandshake += "\x01\x00"

		self.sslStruct['cHelloRB'] = DEFAULT_CH_CLIENT_RANDOM
		self.sslStruct['cHello'] = self.sslHandshake


###############################################################################
#
# read_server_hello --
#
# 			Function to read a ServerHello
#			Message sent by SSL Server
#
# Results:
#			1. Reads ServerHello Message sent by server
#			2. Interprets its details
#			3. Stores necessary values as part of sslStruct
#
# Side Effects:
#			None
###############################################################################
	def read_server_hello(self):
		header = self.socket.recv(5)

		if len(header) == 0:
			self.opn = 1
			return
		shLen = hs2i(header, 3, 4)

		if shLen == 2:
			self.opn = 1

		sHello = ""
		#
		# Added
		#
		if shLen > 500:
			header = self.socket.recv(4)
			shLen = hs2i(header, 1, 3)
			sHello = header
		#

		self.sslStruct['shLen'] = shLen
		sHello = sHello + self.socket.recv(shLen)

		self.sslStruct['sHello'] = sHello
		self.sslStruct['sHelloRB'] = sHello[6:32+6]


###############################################################################
#
# read_server_certificate --
#
# 			Function to read a ServerCertificate Message
#			sent by SSL Server
#
# Results:
#			1. Reads ServerCertificate Message sent by server
#			2. Interprets its details
#			3. Stores necessary values as part of sslStruct
#
# Side Effects:
#			None
###############################################################################
	def read_server_certificate(self):
		header = self.socket.recv(1)
		packet_type = ord(header[0])
		packet_type_h = header[0]
		if packet_type == 22:
			header = self.socket.recv(4)
			if len(header) == 0:
				self.opn = 1
				return
			scLen = hs2i(header, 2, 3)
			self.sslStruct['scLen'] = scLen
			sCertificate = self.socket.recv(scLen)
		else:
			header = self.socket.recv(3)
			if len(header) == 0:
				self.opn = 1
				return
			scLen = hs2i(header, 1, 2)
			self.sslStruct['scLen'] = scLen

			packet_extra = packet_type_h + header
			sCertificate = self.socket.recv(scLen)
			sCertificate = packet_extra + sCertificate

		self.sslStruct['sCertificate'] = sCertificate[10:]
		self.sslStruct['sCertificateCF'] = sCertificate

		fobject = open(serverCert, 'w')
		fobject.write("-----BEGIN CERTIFICATE-----\n")
		output = base64.b64encode(self.sslStruct['sCertificate'])

		count = 0
		final_output = ""
		for iter1 in output:
			final_output += iter1
			count += 1
			if count == 64:
				count = 0
				final_output += "\r\n"

		fobject.write(final_output)
		fobject.write("\n-----END CERTIFICATE-----\n")
		fobject.close()

		sCert = open(serverCert).read()
		self.x509 = X509()
		cert = self.x509.parse(sCert)

		self.x509cc = X509CertChain([self.x509])


###############################################################################
#
# read_server_key_exchange --
#
# 			Function to read a Server Key Exchange Message
#			sent by SSL Server
#
# Results:
#			1. Reads ServerCertificate Message sent by server
#			2. Interprets its details
#			3. Stores necessary values as part of sslStruct
#
# Side Effects:
#			None
###############################################################################
	def read_server_key_exchange(self):
		header = self.socket.recv(5)
		if len(header) == 0:
			self.opn = 1
			return 0
		scLen = hs2i(header, 3, 4)
		self.sslStruct['skeLen'] = scLen
		ske = self.socket.recv(scLen)
		self.sslStruct['ske'] = ske


###############################################################################
#
# read_server_hello_done --
#
# 			Function to read a ServerHelloDone
#			Message sent by SSL Server
#
# Results:
#			1. Reads Server Hello Done Message sent by server
#			2. Interprets its details
#			3. Stores necessary values as part of sslStruct
#
# Side Effects:
#			None
###############################################################################
	def read_server_hello_done(self):
		header = self.socket.recv(1)
		packet_type = ord(header[0])
		packet_type_h = header[0]

		if packet_type == 22:
			header = self.socket.recv(4)
			if len(header) == 0:
				self.opn = 1
				return
			scLen = hs2i(header, 2, 3)
		else:
			header = self.socket.recv(3)
			if len(header) == 0:
				self.opn = 1
				return
			scLen = hs2i(header, 1, 2)

		if scLen > 0:
			sHelloDone = self.socket.recv(scLen)
			self.sslStruct['sHelloDone'] = sHelloDone
		else:
			self.sslStruct['sHelloDone'] = packet_type_h + \
				header


###############################################################################
#
# send_ct_packet --
#
# 			Function to send a cleartext ssl handshake
#			message
#
# Results:
#			1. SSL cleartext record layer header is added
#			2. clear text handshake message is sent
#
# Side Effects:
#			None
###############################################################################

	def send_ct_packet(self):
		recMsg = 	tls12RecHeaderDefault  + \
				pack_2_bytes(len(self.sslHandshake))

		self.sslRecord = recMsg + self.sslHandshake


		try:
			self.socket.send(self.sslRecord)
		except:
			self.opn = 1

##############################################################################
#
# send_ssl_packet --
#
# 			Function to send an SSL handshake packet after adding
#			record layer headers
#
# Results:
#			1. Takes SSL Handshake message as input
#			2. Adds SSL record layer headers to it
#			3. Sends the packet to Server
#
# Side Effects:
#			None
###############################################################################
	def send_ssl_packet(self, hsMsg, seq, renegotiate):
			rec = hsMsg
			recLen = len(rec)
			rec_len_packed = pack('>H', recLen)

			self.seqNum = pack('>Q', seq)

			m = hmac.new(self.sslStruct['wMacPtr'],
				digestmod=sha1)
			m.update(self.seqNum)
			m.update("\x16")
			m.update("\x03")
			m.update("\x03")
			m.update(rec_len_packed)
			m.update(rec)
			m = m.digest()

			#
			# As per 6.2.3.2 (2)(a) in the link below:
			#  http://rfc-ref.org/RFC-TEXTS/4346/chapter6.html
			#
			# Data to be encrypted = R ^ mask + Plain text
			#
			# Mask is set to 0, hence
			#
			# Data to be encrypted = R + Plain text
			#
			# where,
			#  R = A random string of length == block length
			#
			# IV used for encryption is the calculated IV during
			# 	key block creation
			#
			self.display_hex_str("Final MAC", s2hs(m))

			currentLength = len(rec + m) + 1
			blockLength = 16
			pad_len = blockLength - \
				(currentLength % blockLength)

			if pad_len == blockLength:
				pad_len = 0

			self.log("Padding Length: %s" % (str(pad_len)))

			padding = ''
			for iter in range(0, pad_len + 1):
				padding = padding + \
				struct.pack('B', pad_len)

			self.display_hex_str("Padding", s2hs(padding))

			self.sslStruct['recordPlusMAC'] = \
				R + rec + m + padding
			self.display_hex_str("Final Packet", s2hs(
				self.sslStruct['recordPlusMAC']))

			if renegotiate == 1:
				enc_hs_with_reneg = \
AES.new( self.sslStruct['wKeyPtr'], AES.MODE_CBC, self.sslStruct['wIVPtr'])
				encryptedData = \
enc_hs_with_reneg.encrypt(self.sslStruct['recordPlusMAC'])

			if renegotiate == 0:
				enc_hs_wo_reneg = \
AES.new( self.sslStruct['wKeyPtr'], AES.MODE_CBC, self.sslStruct['wIVPtr'] )
				encryptedData = \
enc_hs_wo_reneg.encrypt(self.sslStruct['recordPlusMAC'])


			packLen = len(encryptedData)

			self.sslStruct['encryptedRecordPlusMAC'] = \
				tls12RecHeaderDefault + \
				pack_2_bytes(packLen) + encryptedData
			self.display_hex_str("Encrypted Packet",
				s2hs(self.sslStruct['encryptedRecordPlusMAC']))

			self.socket.send(
				self.sslStruct['encryptedRecordPlusMAC'])



##############################################################################
#
# send_record_packet --
#
# 			Function to send an SSL Application Data after adding
#			record layer headers
#
# Results:
#			1. Takes SSL record message as input
#			2. Adds SSL record layer headers to it
#			3. Sends the packet to Server
#
# Side Effects:
#			None
###############################################################################
	def send_record_packet(self, recMsg, seq):
			rec = recMsg
			recLen = len(rec)
			rec_len_packed = pack('>H', recLen)

			self.seqNum = pack('>Q', seq)

			self.display_hex_str("seq Num", s2hs(self.seqNum))

			m = hmac.new(self.sslStruct['wMacPtr'],
				digestmod=sha1)
			m.update(self.seqNum)
			m.update("\x17")
			m.update("\x03")
			m.update("\x03")
			m.update(rec_len_packed)
			m.update(rec)
			m = m.digest()

			#
			# As per 6.2.3.2 (2)(a) in the link below:
			#  http://rfc-ref.org/RFC-TEXTS/4346/chapter6.html
			#
			# Data to be encrypted = R ^ mask + Plain text
			#
			# Mask is set to 0, hence
			#
			# Data to be encrypted = R + Plain text
			#
			# where,
			#  R = A random string of length == block length
			#
			# IV used for encryption is the calculated IV during
			# 	key block creation
			#
			self.display_hex_str("Final MAC", s2hs(m))

			currentLength = len(rec + m) + 1
			blockLength = len(self.sslStruct['wIVPtr'])
			pad_len = blockLength - \
				(currentLength % blockLength)

			if pad_len == blockLength:
				pad_len = 0

			self.log("Padding Length: %s" % (str(pad_len)))

			padding = ''
			for iter in range(0, pad_len + 1):
				padding = padding + \
				struct.pack('B', pad_len)

			self.display_hex_str("Padding", s2hs(padding))

			self.sslStruct['recordPlusMAC'] = \
				R + rec + m + padding
			self.display_hex_str("Final Packet", s2hs(
				self.sslStruct['recordPlusMAC']))

			enc_rec = AES.new( self.sslStruct['wKeyPtr'], AES.MODE_CBC, self.sslStruct['wIVPtr'])
			encryptedData = \
enc_rec.encrypt(self.sslStruct['recordPlusMAC'])

			packLen = len(encryptedData)

			self.sslStruct['encryptedRecordPlusMAC'] = \
				tls12AppHeaderDefault + \
				pack_2_bytes(packLen) + encryptedData
			self.display_hex_str("Encrypted Packet",
				s2hs(self.sslStruct['encryptedRecordPlusMAC']))

			self.socket.send(
				self.sslStruct['encryptedRecordPlusMAC'])

##############################################################################
#
# read_ct_packet --
#
# 			Function to read cleartext response from server
#
# Results:
#			1. Reads cleartext response from server
#			3. Stores necessary values as part of sslStruct
#
# Side Effects:
#			None
###############################################################################
	def read_ct_packet(self):
			socket = self.socket
			header = self.socket.recv(5)
			recLen = hs2i(header, 3, 4)
			data = self.socket.recv(recLen)
			self.log(str(data))

##############################################################################
#
# read_ssl_packet --
#
# 			Function to read response from server
#
# Results:
#			1. Reads response from server
#			3. Stores necessary values as part of sslStruct
#
# Side Effects:
#			None
###############################################################################
	def read_ssl_packet(self):

		#
		# Read till we receive an encrypted alert
		#
		while True:
			header = self.socket.recv(5)

			if len(header) != 5:
				break
				
			if unpack("B", header[0])[0] == 0x15:
				break
			recLen = hs2i(header, 3, 4)

			try:
				data = self.socket.recv(recLen)
			except:
				self.opn = 1
				return

			self.encHeader = header
			self.encData = data

			dec_rec = AES.new( self.sslStruct['rKeyPtr'],
				AES.MODE_CBC, self.sslStruct['rIVPtr'] )
			self.decrypted_data_part = dec_rec.decrypt(data)


			last_byte = self.decrypted_data_part[len(self.decrypted_data_part) - 1]

			iter = len(self.decrypted_data_part) - 1

			while self.decrypted_data_part[iter] == last_byte:
				iter = iter - 1

			self.decrypted_data_part = self.decrypted_data_part[0:iter]

			self.sslStruct['rIVPtr'] = data[recLen - 16: recLen]
			self.decryptedData += self.decrypted_data_part

			self.display_hex_str("DecryptedData",
				s2hs(self.decrypted_data_part))

##############################################################################
#
# read_sf --
#
# 			Function to read ServerFinished Message from server
#
# Results:
#			1. Reads ChangeCipherSpec and ServerFinished Message
#				from server
#			2. Stores necessary values as part of sslStruct
#			3. Returns True if everything is fine, otherwise False
#
# Side Effects:
#			None
###############################################################################
	def read_sf(self):
			socket = self.socket
			header = self.socket.recv(5)
			CFLen = hs2i(header, 3, 4)
			if CFLen == 1:
				cssSer = self.socket.recv(1)

			if CFLen == 2:
				return False

			header = self.socket.recv(5)
			CFLen = hs2i(header, 3, 4)

			CFMessage = self.socket.recv(CFLen)

			dec_hs = AES.new( self.sslStruct['rKeyPtr'],
				AES.MODE_CBC, self.sslStruct['rIVPtr'] )
			decryptedCF = dec_hs.decrypt(CFMessage)

			self.sslStruct['rIVPtr'] = CFMessage[48:64]
			return True

###############################################################################
#
# P_hash --
#
# 			Function to create a P_Hash
#
# Results:
#			1. Creates a hash based on secret, seed and
#				returns as many bytes as requested
#				in the length parameter
#
# Side Effects:
#			None
###############################################################################
	def P_hash(self, hashModule, secret, seed, length):
	    	bytes = bytearray(length)
	    	A = seed
	    	index = 0
	    	while 1:
			A = hmac.HMAC(secret, A, hashModule).digest()
			output = hmac.HMAC(secret, A+seed, hashModule).digest()
			for c in output:
		    		if index >= length:
		        		return bytes
		    		bytes[index] = c
		    		index += 1

###############################################################################
#
# PRF --
#
# 			Pseudo Random Function
#
# Results:
#			1. TLS PRF is performed by this function
#
# Side Effects:
#			None
###############################################################################
	def PRF(self, secret, label, seed, length):
		seed = label + seed

		p_sha256 = self.P_hash(sha256, secret, seed, length)

	    	return p_sha256


##############################################################################
#
# create_client_key_exchange --
#
# 			Function to create a ClientKeyExchange message
#
# Results:
#			1. Creates ClientKeyExchange Message
#			3. Stores necessary values as part of sslStruct
#
# Side Effects:
#			None
###############################################################################
	def create_client_key_exchange(self):
		#
		# TLS encryption
		#
		sCert = open(serverCert).read()
		x509 = X509()
		cert = x509.parse(sCert)

		x509cc = X509CertChain([x509])
                ckeArray = bytearray(tls12CKEPMKey)
                encData = cert.publicKey.encrypt(ckeArray)
                encDataStr_tls = bytes(encData)


		self.sslStruct['encryptedPMKey'] = encDataStr_tls
		self.sslStruct['encryptedPMKey_len'] = \
			len(self.sslStruct['encryptedPMKey'])

		self.sslStruct['ckeMessage'] = 	ckeMsgHdr + \
			pack_3_bytes(
			self.sslStruct['encryptedPMKey_len'] + 2) + \
			pack_2_bytes(
			self.sslStruct['encryptedPMKey_len']) + \
			self.sslStruct['encryptedPMKey']

		self.encrypted = 0
		self.sslHandshake = self.sslStruct['ckeMessage']

##############################################################################
#
# create_master_secret --
#
# 			Function to create a MasterSecret
#
# Results:
#			1. Creates MasterSecret
#			3. Stores necessary values as part of sslStruct
#
# Side Effects:
#			None
###############################################################################

#
# master_secret = PRF(pre-master secret, "master secret", client random,
#	server random, 48)
#
	def create_master_secret(self):
		self.sslStruct['masterSecret'] = self.PRF(tls12CKEPMKey,
					"master secret",
					self.sslStruct['cHelloRB'] + \
					self.sslStruct['sHelloRB'],
					48)

		master_secret_str = ""
		for ch in self.sslStruct['masterSecret']:
			master_secret_str += chr(ch)

		self.sslStruct['masterSecret'] = master_secret_str


##############################################################################
#
# create_finished_hash --
#
# 			Function to create a ClientFinished MD5 and SHA Hashes
#
# Results:
#			1. Creates ClientFinished MD5 and SHA Hashes
#			3. Stores necessary values as part of sslStruct
#
# Side Effects:
#			None
###############################################################################

#
# ClientFinishedMessage = PRF(master secret, "client finished", shaHash(256) of all handshake messages)
#
#
	def create_finished_hash(self):
		s1 = sha256()
		s1.update(self.sslStruct['cHello'])
		s1.update(self.sslStruct['sHello'])
		s1.update(self.sslStruct['sCertificateCF'])
		s1.update(self.sslStruct['sHelloDone'])
		s1.update(self.sslStruct['ckeMessage'])
		self.shaHash = s1.digest()


		cFinished = self.PRF(self.sslStruct['masterSecret'],
			'client finished',
			self.shaHash, 12)

		cFinished_str = str(cFinished)
		cfLen = len(cFinished_str)
		cfLen = pack_3_bytes(cfLen)

		self.sslStruct['cFinished'] = "\x14" + cfLen + \
					cFinished_str



##############################################################################
#
# create_key_block --
#
# 			Function to create a Key Block
#
# Results:
#			1. Creates a Key Block
#			3. Stores necessary values as part of sslStruct
#
# Side Effects:
#			None
###############################################################################

#
# key_block =
#	  PRF(master_secret + 'key expansion', client random + server random)
#

	def create_key_block(self):
		if self.cipher == "TLS_RSA_WITH_AES_128_CBC_SHA":
			self.sslStruct['macSize'] = 20
			self.sslStruct['keyBits'] = 128
			self.sslStruct['keySize'] = \
				self.sslStruct['keyBits'] / 8
			self.sslStruct['ivSize'] = 16
		elif self.cipher == "TLS_RSA_WITH_AES_256_CBC_SHA":
			self.sslStruct['macSize'] = 20
			self.sslStruct['keyBits'] = 256
			self.sslStruct['keySize'] = \
				self.sslStruct['keyBits'] / 8
			self.sslStruct['ivSize'] = 16

		self.sslStruct['reqKeyLen'] = 2 * self.sslStruct['macSize'] + \
					2 * self.sslStruct['keySize'] + \
					2 * self.sslStruct['ivSize']

		self.sslStruct['keyBlock'] = ""


		seed = self.sslStruct['sHelloRB'] + self.sslStruct['cHelloRB']
		self.sslStruct['keyBlock'] = \
		self.PRF(self.sslStruct['masterSecret'],
			'key expansion', seed, self.sslStruct['reqKeyLen'])


		keyBlock_str = ""
		for ch in self.sslStruct['keyBlock']:
			keyBlock_str += chr(ch)

		self.sslStruct['keyBlock'] = keyBlock_str

		macSize = self.sslStruct['macSize']
		keySize = self.sslStruct['keySize']
		ivSize = self.sslStruct['ivSize']

		self.sslStruct['wMacPtr'] = self.sslStruct['keyBlock']\
			[0:macSize]
		self.sslStruct['rMacPtr'] = self.sslStruct['keyBlock']\
			[macSize:macSize * 2]
		self.sslStruct['wKeyPtr'] = self.sslStruct['keyBlock']\
			[2 * macSize: 2 * macSize + keySize]
		self.sslStruct['rKeyPtr'] = self.sslStruct['keyBlock']\
			[2 * macSize + keySize: 2 * macSize + 2 * keySize]
		self.sslStruct['wIVPtr'] = self.sslStruct['keyBlock']\
			[2 * macSize + 2 * keySize: 2 * macSize + \
				2 * keySize + ivSize]
		self.sslStruct['rIVPtr'] = self.sslStruct['keyBlock']\
			[2 * macSize + \
				2 * keySize + ivSize: 2 * macSize + \
				2 * keySize + 2 * ivSize]

	def print_banner(self, string):
		if self.debugFlag == 1:
			sys.stdout.write("\n### INFO: %s ###\n" % (string))

	def display_hex_str(self, label, string):
		if self.debugFlag == 1:
			sys.stdout.write("\n%s:\n" % (label))
			strList = string.rsplit('0x')
			chNum = 1
			for item in strList[1:]:
				sys.stdout.write(rjust(item, 3, '0'))
				if (chNum == 8):
					sys.stdout.write('-')
				if (chNum == 16):
					sys.stdout.write('\n')
					chNum = 0
				chNum += 1

	def log(self, data):
		if self.debugFlag == 1:
			self.logger.toboth(data)
		else:
			self.logger.tofile(data)
