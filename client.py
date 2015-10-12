import argparse
import binascii
import datetime
import random
import socket
import string
import struct
import sys
import uuid
import filetimes, rpcBind, rpcRequest

from dcerpc import MSRPCHeader, MSRPCBindNak, MSRPCRequestHeader, MSRPCRespHeader
from kmsBase import kmsBase, UUID
from kmsRequestV4 import kmsRequestV4
from kmsRequestV5 import kmsRequestV5
from kmsRequestV6 import kmsRequestV6
from rpcBase import rpcBase

config = {}

def main():
	parser = argparse.ArgumentParser()
	parser.add_argument("ip", action="store", help="The IP address or hostname of the KMS host.", type=str)
	parser.add_argument("port", nargs="?", action="store", default=1688, help="The port the KMS service is listening on. The default is \"1688\".", type=int)
	parser.add_argument("-m", "--mode", dest="mode", choices=["WindowsVista","Windows7","Windows8","Windows81","Office2010","Office2013"], default="Windows7")
	parser.add_argument("-c", "--cmid", dest="cmid", default=None, help="Use this flag to manually specify a CMID to use. If no CMID is specified, a random CMID will be generated.", type=str)
	parser.add_argument("-n", "--name", dest="machineName", default=None, help="Use this flag to manually specify an ASCII machineName to use. If no machineName is specified, a random machineName will be generated.", type=str)
	parser.add_argument("-v", "--verbose", dest="verbose", action="store_const", const=True, default=False, help="Use this flag to enable verbose output.")
	parser.add_argument("-d", "--debug", dest="debug", action="store_const", const=True, default=False, help="Use this flag to enable debug output. Implies \"-v\".")
	config.update(vars(parser.parse_args()))
	checkConfig()
	config['call_id'] = 1
	if config['debug']:
		config['verbose'] = True
	updateConfig()
	s = socket.socket()
	print "Connecting to %s on port %d..." % (config['ip'], config['port'])
	s.connect((config['ip'], config['port']))
	if config['verbose']:
		print "Connection successful!"
	binder = rpcBind.handler(None, config)
	RPC_Bind = str(binder.generateRequest())
	if config['verbose']:
		print "Sending RPC bind request..."
	s.send(RPC_Bind)
	try:
		bindResponse = s.recv(1024)
	except socket.error, e:
		if e[0] == 104:
			print "Error: Connection reset by peer. Exiting..."
			sys.exit()
		else:
			raise
	if bindResponse == '' or not bindResponse:
		print "No data received! Exiting..."
		sys.exit()
	packetType = MSRPCHeader(bindResponse)['type']
	if packetType == rpcBase.packetType['bindAck']:
		if config['verbose']:
			print "RPC bind acknowledged."
		kmsRequest = createKmsRequest()
		requester = rpcRequest.handler(kmsRequest, config)
		s.send(str(requester.generateRequest()))
		response = s.recv(1024)
		if config['debug']:
			print "Response:", binascii.b2a_hex(response)
		parsed = MSRPCRespHeader(response)
		kmsData = readKmsResponse(parsed['pduData'], kmsRequest, config)
		kmsResp = kmsData['response']
		try:
			hwid = kmsData['hwid']
		except:
			hwid = None
		print "KMS Host ePID:", kmsResp['kmsEpid']
		if hwid is not None:
			print "KMS Host HWID:", binascii.b2a_hex(hwid).upper()
		print "KMS Host Current Client Count:", kmsResp['currentClientCount']
		print "KMS VL Activation Interval:", kmsResp['vLActivationInterval']
		print "KMS VL Renewal Interval:", kmsResp['vLRenewalInterval']
	elif packetType == rpcBase.packetType['bindNak']:
		print MSRPCBindNak(bindResponse).dump()
		sys.exit()
	else:
		print "Something went wrong."
		sys.exit()

def checkConfig():
	if config['cmid'] is not None:
		try:
			uuid.UUID(config['cmid'])
		except:
			print "Error: Bad CMID. Exiting..."
			sys.exit()
	if config['machineName'] is not None:
		if len(config['machineName']) < 2 or len(config['machineName']) > 63:
			print "Error: machineName must be between 2 and 63 characters in length."
			sys.exit()

def updateConfig():
	if config['mode'] == 'WindowsVista':
		config['RequiredClientCount'] = 25
		config['KMSProtocolMajorVersion'] = 4
		config['KMSProtocolMinorVersion'] = 0
		config['KMSClientLicenseStatus'] = 2
		config['KMSClientAppID'] = "55c92734-d682-4d71-983e-d6ec3f16059f"
		config['KMSClientSkuID'] = "cfd8ff08-c0d7-452b-9f60-ef5c70c32094"
		config['KMSClientKMSCountedID'] = "212a64dc-43b1-4d3d-a30c-2fc69d2095c6"
	elif config['mode'] == 'Windows7':
		config['RequiredClientCount'] = 25
		config['KMSProtocolMajorVersion'] = 4
		config['KMSProtocolMinorVersion'] = 0
		config['KMSClientLicenseStatus'] = 2
		config['KMSClientAppID'] = "55c92734-d682-4d71-983e-d6ec3f16059f"
		config['KMSClientSkuID'] = "ae2ee509-1b34-41c0-acb7-6d4650168915"
		config['KMSClientKMSCountedID'] = "7fde5219-fbfa-484a-82c9-34d1ad53e856"
	elif config['mode'] == 'Windows8':
		config['RequiredClientCount'] = 25
		config['KMSProtocolMajorVersion'] = 5
		config['KMSProtocolMinorVersion'] = 0
		config['KMSClientLicenseStatus'] = 2
		config['KMSClientAppID'] = "55c92734-d682-4d71-983e-d6ec3f16059f"
		config['KMSClientSkuID'] = "458e1bec-837a-45f6-b9d5-925ed5d299de"
		config['KMSClientKMSCountedID'] = "3c40b358-5948-45af-923b-53d21fcc7e79"
	elif config['mode'] == 'Windows81':
		config['RequiredClientCount'] = 25
		config['KMSProtocolMajorVersion'] = 6
		config['KMSProtocolMinorVersion'] = 0
		config['KMSClientLicenseStatus'] = 2
		config['KMSClientAppID'] = "55c92734-d682-4d71-983e-d6ec3f16059f"
		config['KMSClientSkuID'] = "81671aaf-79d1-4eb1-b004-8cbbe173afea"
		config['KMSClientKMSCountedID'] = "cb8fc780-2c05-495a-9710-85afffc904d7"
	elif config['mode'] == 'Office2010':
		config['RequiredClientCount'] = 5
		config['KMSProtocolMajorVersion'] = 4
		config['KMSProtocolMinorVersion'] = 0
		config['KMSClientLicenseStatus'] = 2
		config['KMSClientAppID'] = "59a52881-a989-479d-af46-f275c6370663"
		config['KMSClientSkuID'] = "6f327760-8c5c-417c-9b61-836a98287e0c"
		config['KMSClientKMSCountedID'] = "e85af946-2e25-47b7-83e1-bebcebeac611"
	elif config['mode'] == 'Office2013':
		config['RequiredClientCount'] = 5
		config['KMSProtocolMajorVersion'] = 5
		config['KMSProtocolMinorVersion'] = 0
		config['KMSClientLicenseStatus'] = 2
		config['KMSClientAppID'] = "0ff1ce15-a989-479d-af46-f275c6370663"
		config['KMSClientSkuID'] = "b322da9c-a2e2-4058-9e4e-f59a6970bd69"
		config['KMSClientKMSCountedID'] = "e6a6f1bf-9d40-40c3-aa9f-c77ba21578c0"

def createKmsRequestBase():
	requestDict = kmsBase.kmsRequestStruct()
	requestDict['versionMinor'] = config['KMSProtocolMinorVersion']
	requestDict['versionMajor'] = config['KMSProtocolMajorVersion']
	requestDict['isClientVm'] = 0
	requestDict['licenseStatus'] = config['KMSClientLicenseStatus']
	requestDict['graceTime'] = 43200
	requestDict['applicationId'] = UUID(uuid.UUID(config['KMSClientAppID']).bytes_le)
	requestDict['skuId'] = UUID(uuid.UUID(config['KMSClientSkuID']).bytes_le)
	requestDict['kmsCountedId'] = UUID(uuid.UUID(config['KMSClientKMSCountedID']).bytes_le)
	requestDict['clientMachineId'] = UUID(uuid.UUID(config['cmid']).bytes_le if (config['cmid'] is not None) else uuid.uuid4().bytes_le)
	requestDict['previousClientMachineId'] = '\0' * 16 #requestDict['clientMachineId'] # I'm pretty sure this is supposed to be a null UUID.
	requestDict['requiredClientCount'] = config['RequiredClientCount']
	requestDict['requestTime'] = filetimes.dt_to_filetime(datetime.datetime.utcnow())
	requestDict['machineName'] = (config['machineName'] if (config['machineName'] is not None) else ''.join(random.choice(string.letters + string.digits) for i in range(random.randint(2,63)))).encode('utf-16le')
	requestDict['mnPad'] = '\0'.encode('utf-16le') * (63 - len(requestDict['machineName'].decode('utf-16le')))

	# Debug Stuff
	if config['debug']:
		print "Request Base Dictionary:", requestDict.dump()

	return requestDict

def createKmsRequest():
	# Update the call ID
	config['call_id'] += 1

	# KMS Protocol Major Version
	if config['KMSProtocolMajorVersion'] == 4:
		handler = kmsRequestV4(None, config)
	elif config['KMSProtocolMajorVersion'] == 5:
		handler = kmsRequestV5(None, config)
	elif config['KMSProtocolMajorVersion'] == 6:
		handler = kmsRequestV6(None, config)
	else:
		return None

	requestBase = createKmsRequestBase()
	return handler.generateRequest(requestBase)

def readKmsResponse(data, request, config):
	if config['KMSProtocolMajorVersion'] == 4:
		print "Received V4 response"
		response = readKmsResponseV4(data, request)
	elif config['KMSProtocolMajorVersion'] == 5:
		print "Received V5 response"
		response = readKmsResponseV5(data)
	elif config['KMSProtocolMajorVersion'] == 6:
		print "Received V6 response"
		response = readKmsResponseV6(data)
	else:
		print "Unhandled response version: %d.%d" % (config['KMSProtocolMajorVersion'], config['KMSProtocolMinorVersion'])
		print "I'm not even sure how this happened..."
	return response

def readKmsResponseV4(data, request):
	response = kmsRequestV4.ResponseV4(data)
	hashed = kmsRequestV4(data, config).generateHash(bytearray(str(response['response'])))
	print "Response Hash has expected value:", hashed == response['hash']
	return response

def readKmsResponseV5(data):
	response = kmsRequestV5.ResponseV5(data)
	decrypted = kmsRequestV5(data, config).decryptResponse(response)
	return decrypted

def readKmsResponseV6(data):
	response = kmsRequestV6.ResponseV5(data)
	decrypted = kmsRequestV6(data, config).decryptResponse(response)
	message = decrypted['message']
	return message

if __name__ == "__main__":
	main()
