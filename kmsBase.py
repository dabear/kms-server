import binascii
import datetime
import filetimes
import kmsPidGenerator
import os
import struct
import sys
import time
import uuid

from structure import Structure

# sqlite3 is optional
try:
	import sqlite3
except:
	pass

class UUID(Structure):
	commonHdr = ()
	structure = (
		('raw', '16s'),
	)

	def get(self):
		return uuid.UUID(bytes_le=str(self))

class kmsBase:
	class kmsRequestStruct(Structure):
		commonHdr = ()
		structure = (
			('versionMinor',            '<H'),
			('versionMajor',            '<H'),
			('isClientVm',              '<I'),
			('licenseStatus',           '<I'),
			('graceTime',               '<I'),
			('applicationId',           ':', UUID),
			('skuId',                   ':', UUID),
			('kmsCountedId' ,           ':', UUID),
			('clientMachineId',         ':', UUID),
			('requiredClientCount',     '<I'),
			('requestTime',             '<Q'),
			('previousClientMachineId', ':', UUID),
			('machineName',             'u'),
			('_mnPad',                  '_-mnPad', '126-len(machineName)'),
			('mnPad',                   ':'),
		)

		def getMachineName(self):
			return self['machineName'].decode('utf-16le')

		def getLicenseStatus(self):
			return kmsBase.licenseStates[self['licenseStatus']] or "Unknown"

	class kmsResponseStruct(Structure):
		commonHdr = ()
		structure = (
			('versionMinor',         '<H'),
			('versionMajor',         '<H'),
			('epidLen',              '<I=len(kmsEpid)+2'),
			('kmsEpid',              'u'),
			('clientMachineId',      ':', UUID),
			('responseTime',         '<Q'),
			('currentClientCount',   '<I'),
			('vLActivationInterval', '<I'),
			('vLRenewalInterval',    '<I'),
		)

	class GenericRequestHeader(Structure):
		commonHdr = ()
		structure = (
			('bodyLength1',  '<I'),
			('bodyLength2',  '<I'),
			('versionMinor', '<H'),
			('versionMajor', '<H'),
			('remainder',    '_'),
		)

	appIds = {
		uuid.UUID("55C92734-D682-4D71-983E-D6EC3F16059F") : "Windows",
		uuid.UUID("59A52881-A989-479D-AF46-F275C6370663") : "Office 14 (2010)",
		uuid.UUID("0FF1CE15-A989-479D-AF46-F275C6370663") : "Office 15 (2013)",
	}

	skuIds = {
		uuid.UUID("ad2542d4-9154-4c6d-8a44-30f11ee96989") : "Windows Server 2008 Standard",
		uuid.UUID("2401e3d0-c50a-4b58-87b2-7e794b7d2607") : "Windows Server 2008 StandardV",
		uuid.UUID("68b6e220-cf09-466b-92d3-45cd964b9509") : "Windows Server 2008 Datacenter",
		uuid.UUID("fd09ef77-5647-4eff-809c-af2b64659a45") : "Windows Server 2008 DatacenterV",
		uuid.UUID("c1af4d90-d1bc-44ca-85d4-003ba33db3b9") : "Windows Server 2008 Enterprise",
		uuid.UUID("8198490a-add0-47b2-b3ba-316b12d647b4") : "Windows Server 2008 EnterpriseV",
		uuid.UUID("ddfa9f7c-f09e-40b9-8c1a-be877a9a7f4b") : "Windows Server 2008 Web",
		uuid.UUID("7afb1156-2c1d-40fc-b260-aab7442b62fe") : "Windows Server 2008 ComputerCluster",
		uuid.UUID("68531fb9-5511-4989-97be-d11a0f55633f") : "Windows Server 2008 R2 Standard",
		uuid.UUID("7482e61b-c589-4b7f-8ecc-46d455ac3b87") : "Windows Server 2008 R2 Datacenter",
		uuid.UUID("620e2b3d-09e7-42fd-802a-17a13652fe7a") : "Windows Server 2008 R2 Enterprise",
		uuid.UUID("a78b8bd9-8017-4df5-b86a-09f756affa7c") : "Windows Server 2008 R2 Web",
		uuid.UUID("cda18cf3-c196-46ad-b289-60c072869994") : "Windows Server 2008 R2 ComputerCluster",
		uuid.UUID("d3643d60-0c42-412d-a7d6-52e6635327f6") : "Windows Server 2012 Datacenter",
		uuid.UUID("f0f5ec41-0d55-4732-af02-440a44a3cf0f") : "Windows Server 2012 Standard",
		uuid.UUID("95fd1c83-7df5-494a-be8b-1300e1c9d1cd") : "Windows Server 2012 MultiPoint Premium",
		uuid.UUID("7d5486c7-e120-4771-b7f1-7b56c6d3170c") : "Windows Server 2012 MultiPoint Standard",
		uuid.UUID("00091344-1ea4-4f37-b789-01750ba6988c") : "Windows Server 2012 R2 Datacenter",
		uuid.UUID("b3ca044e-a358-4d68-9883-aaa2941aca99") : "Windows Server 2012 R2 Standard",
		uuid.UUID("b743a2be-68d4-4dd3-af32-92425b7bb623") : "Windows Server 2012 R2 Cloud Storage",
		uuid.UUID("21db6ba4-9a7b-4a14-9e29-64a60c59301d") : "Windows Server Essentials 2012 R2",
		uuid.UUID("81671aaf-79d1-4eb1-b004-8cbbe173afea") : "Windows 8.1 Enterprise",
		uuid.UUID("113e705c-fa49-48a4-beea-7dd879b46b14") : "Windows 8.1 EnterpriseN",
		uuid.UUID("096ce63d-4fac-48a9-82a9-61ae9e800e5f") : "Windows 8.1 Professional WMC",
		uuid.UUID("c06b6981-d7fd-4a35-b7b4-054742b7af67") : "Windows 8.1 Professional",
		uuid.UUID("7476d79f-8e48-49b4-ab63-4d0b813a16e4") : "Windows 8.1 ProfessionalN",
		uuid.UUID("fe1c3238-432a-43a1-8e25-97e7d1ef10f3") : "Windows 8.1 Core",
		uuid.UUID("78558a64-dc19-43fe-a0d0-8075b2a370a3") : "Windows 8.1 CoreN",
		uuid.UUID("ffee456a-cd87-4390-8e07-16146c672fd0") : "Windows 8.1 Core ARM",
		uuid.UUID("c72c6a1d-f252-4e7e-bdd1-3fca342acb35") : "Windows 8.1 Core Single Language",
		uuid.UUID("db78b74f-ef1c-4892-abfe-1e66b8231df6") : "Windows 8.1 Core Country Specific",
		uuid.UUID("e9942b32-2e55-4197-b0bd-5ff58cba8860") : "Windows 8.1 Core Connected",
		uuid.UUID("c6ddecd6-2354-4c19-909b-306a3058484e") : "Windows 8.1 Core ConnectedN",
		uuid.UUID("b8f5e3a3-ed33-4608-81e1-37d6c9dcfd9c") : "Windows 8.1 Core Connected Single Language",
		uuid.UUID("ba998212-460a-44db-bfb5-71bf09d1c68b") : "Windows 8.1 Core Connected Country Specific",
		uuid.UUID("e58d87b5-8126-4580-80fb-861b22f79296") : "Windows 8.1 Professional Student",
		uuid.UUID("cab491c7-a918-4f60-b502-dab75e334f40") : "Windows 8.1 Professional StudentN",
		uuid.UUID("a00018a3-f20f-4632-bf7c-8daa5351c914") : "Windows 8 Professional WMC",
		uuid.UUID("a98bcd6d-5343-4603-8afe-5908e4611112") : "Windows 8 Professional",
		uuid.UUID("ebf245c1-29a8-4daf-9cb1-38dfc608a8c8") : "Windows 8 ProfessionalN",
		uuid.UUID("458e1bec-837a-45f6-b9d5-925ed5d299de") : "Windows 8 Enterprise",
		uuid.UUID("e14997e7-800a-4cf7-ad10-de4b45b578db") : "Windows 8 EnterpriseN",
		uuid.UUID("c04ed6bf-55c8-4b47-9f8e-5a1f31ceee60") : "Windows 8 Core",
		uuid.UUID("197390a0-65f6-4a95-bdc4-55d58a3b0253") : "Windows 8 CoreN",
		uuid.UUID("ae2ee509-1b34-41c0-acb7-6d4650168915") : "Windows 7 Enterprise",
		uuid.UUID("1cb6d605-11b3-4e14-bb30-da91c8e3983a") : "Windows 7 EnterpriseN",
		uuid.UUID("b92e9980-b9d5-4821-9c94-140f632f6312") : "Windows 7 Professional",
		uuid.UUID("54a09a0d-d57b-4c10-8b69-a842d6590ad5") : "Windows 7 ProfessionalN",
		uuid.UUID("cfd8ff08-c0d7-452b-9f60-ef5c70c32094") : "Windows Vista Enterprise",
		uuid.UUID("d4f54950-26f2-4fb4-ba21-ffab16afcade") : "Windows Vista EnterpriseN",
		uuid.UUID("4f3d1606-3fea-4c01-be3c-8d671c401e3b") : "Windows Vista Business",
		uuid.UUID("2c682dc2-8b68-4f63-a165-ae291d4cf138") : "Windows Vista BusinessN",
		uuid.UUID("aa6dd3aa-c2b4-40e2-a544-a6bbb3f5c395") : "Windows ThinPC",
		uuid.UUID("db537896-376f-48ae-a492-53d0547773d0") : "Windows Embedded POSReady 7",
		uuid.UUID("0ab82d54-47f4-4acb-818c-cc5bf0ecb649") : "Windows Embedded Industry 8.1",
		uuid.UUID("cd4e2d9f-5059-4a50-a92d-05d5bb1267c7") : "Windows Embedded IndustryE 8.1",
		uuid.UUID("f7e88590-dfc7-4c78-bccb-6f3865b99d1a") : "Windows Embedded IndustryA 8.1",
		uuid.UUID("8ce7e872-188c-4b98-9d90-f8f90b7aad02") : "Office Access 2010",
		uuid.UUID("cee5d470-6e3b-4fcc-8c2b-d17428568a9f") : "Office Excel 2010",
		uuid.UUID("8947d0b8-c33b-43e1-8c56-9b674c052832") : "Office Groove 2010",
		uuid.UUID("ca6b6639-4ad6-40ae-a575-14dee07f6430") : "Office InfoPath 2010",
		uuid.UUID("09ed9640-f020-400a-acd8-d7d867dfd9c2") : "Office Mondo 2010",
		uuid.UUID("ef3d4e49-a53d-4d81-a2b1-2ca6c2556b2c") : "Office Mondo 2010",
		uuid.UUID("ab586f5c-5256-4632-962f-fefd8b49e6f4") : "Office OneNote 2010",
		uuid.UUID("ecb7c192-73ab-4ded-acf4-2399b095d0cc") : "Office OutLook 2010",
		uuid.UUID("45593b1d-dfb1-4e91-bbfb-2d5d0ce2227a") : "Office PowerPoint 2010",
		uuid.UUID("df133ff7-bf14-4f95-afe3-7b48e7e331ef") : "Office Project Pro 2010",
		uuid.UUID("5dc7bf61-5ec9-4996-9ccb-df806a2d0efe") : "Office Project Standard 2010",
		uuid.UUID("b50c4f75-599b-43e8-8dcd-1081a7967241") : "Office Publisher 2010",
		uuid.UUID("92236105-bb67-494f-94c7-7f7a607929bd") : "Office Visio Premium 2010",
		uuid.UUID("e558389c-83c3-4b29-adfe-5e4d7f46c358") : "Office Visio Pro 2010",
		uuid.UUID("9ed833ff-4f92-4f36-b370-8683a4f13275") : "Office Visio Standard 2010",
		uuid.UUID("2d0882e7-a4e7-423b-8ccc-70d91e0158b1") : "Office Word 2010",
		uuid.UUID("6f327760-8c5c-417c-9b61-836a98287e0c") : "Office Professional Plus 2010",
		uuid.UUID("9da2a678-fb6b-4e67-ab84-60dd6a9c819a") : "Office Standard 2010",
		uuid.UUID("ea509e87-07a1-4a45-9edc-eba5a39f36af") : "Office Small Business Basics 2010",
		uuid.UUID("6ee7622c-18d8-4005-9fb7-92db644a279b") : "Office Access 2013",
		uuid.UUID("f7461d52-7c2b-43b2-8744-ea958e0bd09a") : "Office Excel 2013",
		uuid.UUID("a30b8040-d68a-423f-b0b5-9ce292ea5a8f") : "Office InfoPath 2013",
		uuid.UUID("1b9f11e3-c85c-4e1b-bb29-879ad2c909e3") : "Office Lync 2013",
		uuid.UUID("dc981c6b-fc8e-420f-aa43-f8f33e5c0923") : "Office Mondo 2013",
		uuid.UUID("efe1f3e6-aea2-4144-a208-32aa872b6545") : "Office OneNote 2013",
		uuid.UUID("771c3afa-50c5-443f-b151-ff2546d863a0") : "Office OutLook 2013",
		uuid.UUID("8c762649-97d1-4953-ad27-b7e2c25b972e") : "Office PowerPoint 2013",
		uuid.UUID("4a5d124a-e620-44ba-b6ff-658961b33b9a") : "Office Project Pro 2013",
		uuid.UUID("427a28d1-d17c-4abf-b717-32c780ba6f07") : "Office Project Standard 2013",
		uuid.UUID("00c79ff1-6850-443d-bf61-71cde0de305f") : "Office Publisher 2013",
		uuid.UUID("b13afb38-cd79-4ae5-9f7f-eed058d750ca") : "Office Visio Standard 2013",
		uuid.UUID("e13ac10e-75d0-4aff-a0cd-764982cf541c") : "Office Visio Pro 2013",
		uuid.UUID("d9f5b1c6-5386-495a-88f9-9ad6b41ac9b3") : "Office Word 2013",
		uuid.UUID("b322da9c-a2e2-4058-9e4e-f59a6970bd69") : "Office Professional Plus 2013",
		uuid.UUID("b13afb38-cd79-4ae5-9f7f-eed058d750ca") : "Office Standard 2013",
		uuid.UUID("ba947c44-d19d-4786-b6ae-22770bc94c54") : "Windows Server 2015 Datacenter TechPreview",
		#patched by dabear
		#uuid.UUID("a4383e6b-dada-423d-a43d-f25678429676") : "Windows 10 Professional TechPreview",
		#uuid.UUID("cf59a07b-1a2a-4be0-bfe0-423b5823e663") : "Windows 10 Professional WMC TechPreview",
		#uuid.UUID("cde952c7-2f96-4d9d-8f2b-2d349f64fc51") : "Windows 10 Enterprise TechPreview",
		#patched by dabear
		uuid.UUID("d450596f-894d-49e0-966a-fd39ed4c4c64") : "Office Professional Plus 2016",
        uuid.UUID("dedfa23d-6ed1-45a6-85dc-63cae0546de6") : "Office Standard 2016",                
        uuid.UUID("4f414197-0fc2-4c01-b68a-86cbb9ac254c") : "Office Project Pro 2016",
        uuid.UUID("da7ddabc-3fbe-4447-9e01-6ab7440b4cd4") : "Office Project Standard 2016",            
        uuid.UUID("6bf301c1-b94a-43e9-ba31-d494598c47fb") : "Office Visio Pro 2016",
        uuid.UUID("aa2a7821-1827-4c2c-8f1d-4513a34dda97") : "Office Visio Standard 2016",                
        uuid.UUID("041a06cb-c5b8-4772-809f-416d03d16654") : "Office Publisher 2016",
        uuid.UUID("67c0fc0c-deba-401b-bf8b-9c8ad8395804") : "Office Access 2016",
        uuid.UUID("83e04ee1-fa8d-436d-8994-d31a862cab77") : "Office Skype for Business 2016",
        uuid.UUID("9caabccb-61b1-4b4b-8bec-d10a3c3ac2ce") : "Office Mondo 2016",
        uuid.UUID("e914ea6e-a5fa-4439-a394-a9bb3293ca09") : "Office Mondo R 2016",            
        uuid.UUID("bb11badf-d8aa-470e-9311-20eaf80fe5cc") : "Office Word 2016",
        uuid.UUID("c3e65d36-141f-4d2f-a303-a842ee756a29") : "Office Excel 2016",
        uuid.UUID("d70b1bba-b893-4544-96e2-b7a318091c33") : "Office Powerpoint 2016",
        uuid.UUID("d8cace59-33d2-4ac7-9b1b-9b72339c51c8") : "Office OneNote 2016",
        uuid.UUID("ec9d9265-9d1e-4ed0-838a-cdc20f2551a1") : "Office Outlook 2016",                
        uuid.UUID("a4383e6b-dada-423d-a43d-f25678429676") : "Windows 10 Professional TechPreview",
        uuid.UUID("cf59a07b-1a2a-4be0-bfe0-423b5823e663") : "Windows 10 Professional WMC TechPreview",
        uuid.UUID("cde952c7-2f96-4d9d-8f2b-2d349f64fc51") : "Windows 10 Enterprise TechPreview",
        uuid.UUID("6496e59d-89dc-49eb-a353-09ceb9404845") : "Windows 10 Core TechPreview",
        uuid.UUID("73111121-5638-40f6-bc11-f1d7b0d64300") : "Windows 10 Enterprise",
        uuid.UUID("e272e3e2-732f-4c65-a8f0-484747d0d947") : "Windows 10 Enterprise N",
        uuid.UUID("7b51a46c-0c04-4e8f-9af4-8496cca90d5e") : "Windows 10 Enterprise LTSB",
        uuid.UUID("87b838b7-41b6-4590-8318-5797951d8529") : "Windows 10 Enterprise LTSB N",
        uuid.UUID("e0c42288-980c-4788-a014-c080d2e1926e") : "Windows 10 Education",
        uuid.UUID("3c102355-d027-42c6-ad23-2e7ef8a02585") : "Windows 10 Education N",
        uuid.UUID("2de67392-b7a7-462a-b1ca-108dd189f588") : "Windows 10 Professional",
        #uuid.UUID("a80b5abf-76ad-1234567890123428b-b05d-a47d2dffeebf") : "Windows 10 Professional N",
        uuid.UUID("58e97c99-f377-4ef1-81d5-4ad5522b5fd8") : "Windows 10 Home",
        uuid.UUID("7b9e1751-a8da-4f75-9560-5fadfe3d8e38") : "Windows 10 Home N",
        uuid.UUID("cd918a57-a41b-4c82-8dce-1a538e221a83") : "Windows 10 Home Single Language",
        uuid.UUID("a9107544-f4a0-4053-a96a-1479abdef912") : "Windows 10 Home Country Specific",
	}

	licenseStates = {
		0 : "Unlicensed",
		1 : "Activated",
		2 : "Grace Period",
		3 : "Out-of-Tolerance Grace Period",
		4 : "Non-Genuine Grace Period",
		5 : "Notifications Mode",
		6 : "Extended Grace Period",
	}

	licenseStatesEnum = {
		'unlicensed' : 0,
		'licensed' : 1,
		'oobGrace' : 2,
		'ootGrace' : 3,
		'nonGenuineGrace' : 4,
		'notification' : 5,
		'extendedGrace' : 6
	}

	errorCodes = {
		'SL_E_VL_NOT_WINDOWS_SLP' : 0xC004F035,
		'SL_E_VL_NOT_ENOUGH_COUNT' : 0xC004F038,
		'SL_E_VL_BINDING_SERVICE_NOT_ENABLED' : 0xC004F039,
		'SL_E_VL_INFO_PRODUCT_USER_RIGHT' : 0x4004F040,
		'SL_I_VL_OOB_NO_BINDING_SERVER_REGISTRATION' : 0x4004F041,
		'SL_E_VL_KEY_MANAGEMENT_SERVICE_ID_MISMATCH' : 0xC004F042,
		'SL_E_VL_MACHINE_NOT_BOUND' : 0xC004F056
	}

	def __init__(self, data, config):
		self.data = data
		self.config = config

	def getConfig(self):
		return self.config

	def getOptions(self):
		return self.config

	def getData(self):
		return self.data

	def getResponse(self):
		return ''

	def getResponsePadding(self, bodyLength):
		if bodyLength % 8 == 0:
			paddingLength = 0
		else:
			paddingLength = 8 - bodyLength % 8
		padding = bytearray(paddingLength)
		return padding

	def serverLogic(self, kmsRequest):
		if self.config['sqlite'] and self.config['dbSupport']:
			self.dbName = 'clients.db'
			if not os.path.isfile(self.dbName):
				# Initialize the database.
				con = None
				try:
					con = sqlite3.connect(self.dbName)
					cur = con.cursor()
					cur.execute("CREATE TABLE clients(clientMachineId TEXT, machineName TEXT, applicationId TEXT, skuId TEXT, licenseStatus TEXT, lastRequestTime INTEGER, kmsEpid TEXT, requestCount INTEGER)")

				except sqlite3.Error, e:
					print "Error %s:" % e.args[0]
					sys.exit(1)

				finally:
					if con:
						con.commit()
						con.close()

		if self.config['debug']:
			print "KMS Request Bytes:", binascii.b2a_hex(str(kmsRequest))
			print "KMS Request:", kmsRequest.dump()

		clientMachineId = kmsRequest['clientMachineId'].get()
		applicationId = kmsRequest['applicationId'].get()
		skuId = kmsRequest['skuId'].get()
		requestDatetime = filetimes.filetime_to_dt(kmsRequest['requestTime'])

		# Try and localize the request time, if pytz is available
		try:
			import timezones
			from pytz import utc
			local_dt = utc.localize(requestDatetime).astimezone(timezones.localtz())
		except ImportError:
			local_dt = requestDatetime

		infoDict = {
			"machineName" : kmsRequest.getMachineName(),
			"clientMachineId" : str(clientMachineId),
			"appId" : self.appIds.get(applicationId, str(applicationId)),
			"skuId" : self.skuIds.get(skuId, str(skuId)),
			"licenseStatus" : kmsRequest.getLicenseStatus(),
			"requestTime" : int(time.time()),
			"kmsEpid" : None
		}

		#print infoDict

		if self.config['verbose']:
			print "     Machine Name: %s" % infoDict["machineName"]
			print "Client Machine ID: %s" % infoDict["clientMachineId"]
			print "   Application ID: %s" % infoDict["appId"]
			print "           SKU ID: %s" % infoDict["skuId"]
			print "   Licence Status: %s" % infoDict["licenseStatus"]
			print "     Request Time: %s" % local_dt.strftime('%Y-%m-%d %H:%M:%S %Z (UTC%z)')

		if self.config['sqlite'] and self.config['dbSupport']:
			con = None
			try:
				con = sqlite3.connect(self.dbName)
				cur = con.cursor()
				cur.execute("SELECT * FROM clients WHERE clientMachineId=:clientMachineId;", infoDict)
				try:
					data = cur.fetchone()
					if not data:
						#print "Inserting row..."
						cur.execute("INSERT INTO clients (clientMachineId, machineName, applicationId, skuId, licenseStatus, lastRequestTime, requestCount) VALUES (:clientMachineId, :machineName, :appId, :skuId, :licenseStatus, :requestTime, 1);", infoDict)
					else:
						#print "Data:", data
						if data[1] != infoDict["machineName"]:
							cur.execute("UPDATE clients SET machineName=:machineName WHERE clientMachineId=:clientMachineId;", infoDict)
						if data[2] != infoDict["appId"]:
							cur.execute("UPDATE clients SET applicationId=:appId WHERE clientMachineId=:clientMachineId;", infoDict)
						if data[3] != infoDict["skuId"]:
							cur.execute("UPDATE clients SET skuId=:skuId WHERE clientMachineId=:clientMachineId;", infoDict)
						if data[4] != infoDict["licenseStatus"]:
							cur.execute("UPDATE clients SET licenseStatus=:licenseStatus WHERE clientMachineId=:clientMachineId;", infoDict)
						if data[5] != infoDict["requestTime"]:
							cur.execute("UPDATE clients SET lastRequestTime=:requestTime WHERE clientMachineId=:clientMachineId;", infoDict)
						# Increment requestCount
						cur.execute("UPDATE clients SET requestCount=requestCount+1 WHERE clientMachineId=:clientMachineId;", infoDict)

				except sqlite3.Error, e:
					print "Error %s:" % e.args[0]

			except sqlite3.Error, e:
				print "Error %s:" % e.args[0]
				sys.exit(1)

			finally:
				if con:
					con.commit()
					con.close()

		return self.createKmsResponse(kmsRequest)

	def createKmsResponse(self, kmsRequest):
		response = self.kmsResponseStruct()
		response['versionMinor'] = kmsRequest['versionMinor']
		response['versionMajor'] = kmsRequest['versionMajor']

		if not self.config["epid"]:
			response["kmsEpid"] = kmsPidGenerator.epidGenerator(kmsRequest['applicationId'], kmsRequest['versionMajor'], self.config["lcid"]).encode('utf-16le')
		else:
			response["kmsEpid"] = self.config["epid"].encode('utf-16le')
		response['clientMachineId'] = kmsRequest['clientMachineId']
		response['responseTime'] = kmsRequest['requestTime']
		response['currentClientCount'] = self.config["CurrentClientCount"]
		response['vLActivationInterval'] = self.config["VLActivationInterval"]
		response['vLRenewalInterval'] = self.config["VLRenewalInterval"]

		if self.config['sqlite'] and self.config['dbSupport']:
			con = None
			try:
				con = sqlite3.connect(self.dbName)
				cur = con.cursor()
				cur.execute("SELECT * FROM clients WHERE clientMachineId=?;", [str(kmsRequest['clientMachineId'].get())])
				try:
					data = cur.fetchone()
					#print "Data:", data
					if data[6]:
						response["kmsEpid"] = data[6].encode('utf-16le')
					else:
						cur.execute("UPDATE clients SET kmsEpid=? WHERE clientMachineId=?;", (str(response["kmsEpid"].decode('utf-16le')), str(kmsRequest['clientMachineId'].get())))

				except sqlite3.Error, e:
					print "Error %s:" % e.args[0]

			except sqlite3.Error, e:
				print "Error %s:" % e.args[0]
				sys.exit(1)

			finally:
				if con:
					con.commit()
					con.close()

		if self.config['verbose']:
			print "      Server ePID: %s" % response["kmsEpid"].decode('utf-16le')
		return response

import kmsRequestV4, kmsRequestV5, kmsRequestV6, kmsRequestUnknown

def generateKmsResponseData(data, config):
	version = kmsBase.GenericRequestHeader(data)['versionMajor']
	currentDate = datetime.datetime.now().ctime()

	if version == 4:
		print "Received V%d request on %s." % (version, currentDate)
		messagehandler = kmsRequestV4.kmsRequestV4(data, config)
		messagehandler.executeRequestLogic()
	elif version == 5:
		print "Received V%d request on %s." % (version, currentDate)
		messagehandler = kmsRequestV5.kmsRequestV5(data, config)
		messagehandler.executeRequestLogic()
	elif version == 6:
		print "Received V%d request on %s." % (version, currentDate)
		messagehandler = kmsRequestV6.kmsRequestV6(data, config)
		messagehandler.executeRequestLogic()
	else:
		print "Unhandled KMS version.", version
		messagehandler = kmsRequestUnknown.kmsRequestUnknown(data, config)
	return messagehandler.getResponse()
