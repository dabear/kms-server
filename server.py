import argparse
import binascii
import hashlib
import random
import re
import socket
import SocketServer
import struct
import uuid
import rpcBind, rpcRequest

from dcerpc import MSRPCHeader
from rpcBase import rpcBase

config = {}

def main():
	parser = argparse.ArgumentParser(description='KMS Server Emulator', epilog="version: py-kms_2014-10-13 build 1")
	#parser = argparse.ArgumentParser()
	parser.add_argument("ip", nargs="?", action="store", default="0.0.0.0", help="The IP address to listen on. The default is \"0.0.0.0\" (all interfaces).", type=str)
	parser.add_argument("port", nargs="?", action="store", default=1688, help="The network port to listen on. The default is \"1688\".", type=int)
	parser.add_argument("-e", "--epid", dest="epid", default=None, help="Use this flag to manually specify an ePID to use. If no ePID is specified, a random ePID will be generated.", type=str)
	parser.add_argument("-l", "--lcid", dest="lcid", default=1033, help="Use this flag to manually specify an LCID for use with randomly generated ePIDs. If an ePID is manually specified, this setting is ignored.", type=int)
	parser.add_argument("-c", "--client-count", dest="CurrentClientCount", default=26, help="Use this flag to specify the current client count. Default is 26. A number >25 is required to enable activation.", type=int)
	parser.add_argument("-a", "--activation-interval", dest="VLActivationInterval", default=120, help="Use this flag to specify the activation interval (in minutes). Default is 120 minutes (2 hours).", type=int)
	parser.add_argument("-r", "--renewal-interval", dest="VLRenewalInterval", default=1440 * 7, help="Use this flag to specify the renewal interval (in minutes). Default is 10080 minutes (7 days).", type=int)
	parser.add_argument("-v", "--verbose", dest="verbose", action="store_const", const=True, default=False, help="Use this flag to enable verbose output.")
	parser.add_argument("-d", "--debug", dest="debug", action="store_const", const=True, default=False, help="Use this flag to enable debug output. Implies \"-v\".")
	parser.add_argument("-s", "--sqlite", dest="sqlite", action="store_const", const=True, default=False, help="Use this flag to store request information from unique clients in an SQLite database.")
	parser.add_argument("-o", "--log", dest="log", action="store_const", const=True, default=False, help="Use this flag to enable logging to a file.")
	parser.add_argument("-w", "--hwid", dest="hwid", action="store", default='364F463A8863D35F', help="Use this flag to specify a HWID. The HWID must be an 16-character string of hex characters. The default is \"364F463A8863D35F\" or type \"random\" to auto generate the HWID.")	
	
	config.update(vars(parser.parse_args()))
	
	#Random HWID
	if config['hwid'] == "random":
		randomhwid = uuid.uuid4().hex
		config['hwid'] = randomhwid[:16]
	
	# Sanitize HWID
	try:
		config['hwid'] = binascii.a2b_hex(re.sub(r'[^0-9a-fA-F]', '', config['hwid'].strip('0x')))
		if len(binascii.b2a_hex(config['hwid'])) < 16:
			print "Error: HWID \"%s\" is invalid. Hex string is too short." % binascii.b2a_hex(config['hwid'])
			return
		elif len(binascii.b2a_hex(config['hwid'])) > 16:
			print "Error: HWID \"%s\" is invalid. Hex string is too long." % binascii.b2a_hex(config['hwid'])
			return
	except TypeError:
		print "Error: HWID \"%s\" is invalid. Odd-length hex string." % binascii.b2a_hex(config['hwid'])
		return
	if config['debug']:
		config['verbose'] = True
	try:
		import sqlite3
		config['dbSupport'] = True
	except:
		print "Warning: Module \"sqlite3\" is not installed--database support disabled."
		config['dbSupport'] = False
	server = SocketServer.TCPServer((config['ip'], config['port']), kmsServer)
	server.timeout = 5
	print "TCP server listening at %s on port %d." % (config['ip'],config['port'])
	print "HWID: ", binascii.b2a_hex(config['hwid'])
	server.serve_forever()

class kmsServer(SocketServer.BaseRequestHandler):
	def setup(self):
		self.connection = self.request
		print "Connection accepted: %s:%d" % (self.client_address[0],self.client_address[1])

	def handle(self):
		while True:
			# self.request is the TCP socket connected to the client
			try:
				self.data = self.connection.recv(1024)
			except socket.error, e:
				if e[0] == 104:
					print "Error: Connection reset by peer."
					break
				else:
					raise
			if self.data == '' or not self.data:
				print "No data received!"
				break
			# self.data = bytearray(self.data.strip())
			# print binascii.b2a_hex(str(self.data))
			packetType = MSRPCHeader(self.data)['type']
			if packetType == rpcBase.packetType['bindReq']:
				if config['verbose']:
					print "RPC bind request received."
				handler = rpcBind.handler(self.data, config)
			elif packetType == rpcBase.packetType['request']:
				if config['verbose']:
					print "Received activation request."
				handler = rpcRequest.handler(self.data, config)
			else:
				print "Error: Invalid RPC request type", packetType
				break

			handler.populate()
			res = str(handler.getResponse())
			self.connection.send(res)

			if packetType == rpcBase.packetType['bindReq']:
				if config['verbose']:
					print "RPC bind acknowledged."
			elif packetType == rpcBase.packetType['request']:
				if config['verbose']:
					print "Responded to activation request."
				break

	def finish(self):
		self.connection.close()
		print "Connection closed: %s:%d" % (self.client_address[0],self.client_address[1])

if __name__ == "__main__":
	main()
