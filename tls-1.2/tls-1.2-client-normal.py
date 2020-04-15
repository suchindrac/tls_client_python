import sys
from tls1_2API import *
from s_functions import *
from tlslite.api import *
from logger import *
import socket, sys, random, time, getopt, copy, os

def usage():
	print 	"<program name> \r\n\r\n \
[-h | --help] \r\n \
--host=|-o <host IP> \r\n \
--port=|-p <port number> \r\n \
--log|-l <log file> \r\n \
--debug|-d \r\n \
--cipher|-x \r\n \
 	TLS_RSA_WITH_AES_128_CBC_SHA \r\n \
	TLS_RSA_WITH_AES_256_CBC_SHA \r\n \
"

host = port = test_case = rng = value = seq = cipher_value = log_file = comm = cipher = None
spaces = "                 "
debugFlag = 0

try:
	opts, args = getopt.getopt(sys.argv[1:], "ho:p:l:dx:",
		["help", "host=", "port=", "log=", "debug=", "cipher="])
except getopt.GetoptError, err:
        print str(err) # will print something like "option -a not recognized"
        usage()
        sys.exit(1)

for o, a in opts:
       	if o in ("-h", "--help"):
	        usage()
		sys.exit()
  	elif o in ("-o", "--host"):
		host = a
	elif o in ("-p", "--port"):
		port = int(a, 10)
	elif o in ("-l", "--log"):
		log_file = a
	elif o in ("-d", "--debug"):
		debugFlag = 1
	elif o in ("-x", "--cipher"):
		cipher = a
		print (cipher)
	else:
		print ("Invalid arguments supplied")

if (host == None) or (port == None):
	usage()
	sys.exit(2)

#
# set logger
#
if log_file == None:
	print "Invalid log file specified"
	usage()
	sys.exit(1)

logger = logger(log_file)
if logger.read_error == 1:
	print "Unable to open log file for writing"
	sys.exit(1)

tls_lib = lib_tls(host, port, logger, cipher = cipher, debugFlag = debugFlag)

logger.toboth("starting TLS 1.2 handshake")
tls_lib.tcp_connect()
tls_lib.log("Creating ClientHello")
tls_lib.create_client_hello()
tls_lib.log("Length of ClientHello:%s\n" % \
	str(len(tls_lib.sslStruct['cHello'])))

tls_lib.display_hex_str("ClientHello Message",
	s2hs(tls_lib.sslStruct['cHello']))

tls_lib.log("Sending packet")
tls_lib.send_ct_packet()
tls_lib.log("Reading ServerHello")
tls_lib.read_server_hello()
tls_lib.display_hex_str("ServerHello Message Received",
	s2hs(tls_lib.sslStruct['sHello']))
tls_lib.display_hex_str("ServerHello Random Bytes",
	s2hs(tls_lib.sslStruct['sHelloRB']))

if tls_lib.opn == 1:
	logger.toboth("Server did not respond properly")
	sys.exit(1)

tls_lib.log("Reading server Certificate")
tls_lib.read_server_certificate()
if tls_lib.opn == 1:
	logger.toboth("Server did not respond properly")
	sys.exit(1)
tls_lib.display_hex_str("Server Certificate",
	s2hs(tls_lib.sslStruct['sCertificate']))
tls_lib.display_hex_str("Server Certificate CF",
	s2hs(tls_lib.sslStruct['sCertificateCF']))
tls_lib.display_hex_str("Fingerprint",s2hs(tls_lib.x509.getFingerprint()))
logger.tofile("Number of Certificates: " + str(tls_lib.x509cc.getNumCerts()))
tls_lib.log("Read ServerCertificate")

tls_lib.log("Reading ServerHelloDone")
tls_lib.read_server_hello_done()
if tls_lib.opn == 1:
	logger.toboth("Server did not respond properly")
	sys.exit(1)
tls_lib.display_hex_str("Server HelloDone",
	s2hs(tls_lib.sslStruct['sHelloDone']))
tls_lib.log("Read ServerHelloDone")

tls_lib.log("Creating client key exchange")
tls_lib.create_client_key_exchange()
tls_lib.display_hex_str("Client KeyExchange Message",
	s2hs(tls_lib.sslStruct['ckeMessage']))
tls_lib.display_hex_str("Client Encrypted Pre Master Key",
	s2hs(tls_lib.sslStruct['encryptedPMKey']))
tls_lib.display_hex_str("Client ChangeCipherSpec Message",
	s2hs(cssPkt))

tls_lib.log("sending ClientKeyExchange")
tls_lib.send_ct_packet()

tls_lib.log("sending CSS packet")
tls_lib.socket.send(tls12CSSPkt)
if tls_lib.opn == 1:
	logger.toboth("Server did not respond properly")
	sys.exit(1)

tls_lib.log("Creating master secret")
tls_lib.display_hex_str("ClientRandom:",
	s2hs(tls_lib.sslStruct['cHelloRB']))
tls_lib.display_hex_str("ServerRandom:",
	s2hs(tls_lib.sslStruct['sHelloRB']))
tls_lib.display_hex_str("ckePMKey:", s2hs(ckePMKey))

tls_lib.create_master_secret()

tls_lib.display_hex_str("MasterSecret",
	s2hs(tls_lib.sslStruct['masterSecret']))
tls_lib.log("Created MasterSecret")

tls_lib.log("Creating finished hash")
tls_lib.display_hex_str("ClientHello", s2hs(tls_lib.sslStruct['cHello']))
tls_lib.display_hex_str("ServerHello", s2hs(tls_lib.sslStruct['sHello']))
tls_lib.display_hex_str("Server Certificate",
	s2hs(tls_lib.sslStruct['sCertificateCF']))
tls_lib.display_hex_str("Server Hello Done",
	s2hs(tls_lib.sslStruct['sHelloDone']))
tls_lib.display_hex_str("Client Key Exchange",
	s2hs(tls_lib.sslStruct['ckeMessage']))
tls_lib.display_hex_str("Master Secret",
	s2hs(tls_lib.sslStruct['masterSecret']))

tls_lib.create_finished_hash()

tls_lib.display_hex_str("SHA Hash", s2hs(tls_lib.shaHash))
tls_lib.display_hex_str("ClientFinished Message",
	s2hs(tls_lib.sslStruct['cFinished']))
tls_lib.log("Created Finished Hash")

tls_lib.log("Creating key block")
tls_lib.create_key_block()
tls_lib.display_hex_str("Key Block", s2hs(tls_lib.sslStruct['keyBlock']))
tls_lib.display_hex_str("wMacPtr", s2hs(tls_lib.sslStruct['wMacPtr']))
tls_lib.display_hex_str("rMacPtr", s2hs(tls_lib.sslStruct['rMacPtr']))
tls_lib.display_hex_str("wKeyPtr", s2hs(tls_lib.sslStruct['wKeyPtr']))
tls_lib.display_hex_str("rKeyPtr", s2hs(tls_lib.sslStruct['rKeyPtr']))
tls_lib.display_hex_str("wIVPtr", s2hs(tls_lib.sslStruct['wIVPtr']))
tls_lib.display_hex_str("rIVPtr", s2hs(tls_lib.sslStruct['rIVPtr']))
tls_lib.log("Created Key Block")

tls_lib.log("sending Client Finished")
tls_lib.send_ssl_packet(tls_lib.sslStruct['cFinished'], 0, 0)
tls_lib.log("sent Client Finished")

tls_lib.log("Reading server finished")
result = tls_lib.read_sf()
if result == True:
	logger.toboth("Read server finished")
else:
	logger.toboth("Server sent Decrypt Error alert instead of Server Finished")
	sys.exit(1)

logger.toboth("TLS handshake completed")

req1 = "GET / HTTP/1.1\r\n\r\n"

tls_lib.log("Sending data")
tls_lib.display_hex_str("Data", s2hs(req1))
tls_lib.send_record_packet(req1, 1)
tls_lib.log("send data")

tls_lib.log("Reading SSL packet")
tls_lib.read_ssl_packet()
sys.stdout.write("\nData received: \n%s\n" % (tls_lib.decryptedData))

tls_lib.log("Read SSL packet completed")

# tls_lib.send_ssl_packet(sDesc, tls_lib.sslStruct['cHello'], 1, 1)
