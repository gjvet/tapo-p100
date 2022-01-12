import utils.TpLinkCipher as cipher
import hashlib
import requests
import ast
import time
import json
import uuid
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from base64 import b64decode

ERROR_CODES = {
	'0': 'Success',
    '-1010': 'Invalid Public Key Length',
	'-1012': 'Invalid terminalUUID',
	'-1501': 'Invalid Request or Credentials',
	'1002': 'Incorrect Request',
	'-1003': 'JSON formatting error ',
	'9999': 'Session Timeout',
	'-1301': 'Device Error',
	'1100': 'Handshake Failed',
	'1111': 'Login Failed',
	'1112': 'Http Transport Failed',
	'1200': 'Multiple Requests Failed',
	'-1004': 'JSON Encode Failed',
	'-1005': 'AES Decode Failed',
	'-1006': 'Request Length Error',
	'-2101': 'Account Error',
	'-1': 'ERR_COMMON_FAILED',
	'1000': 'ERR_NULL_TRANSPORT',
	'1001': 'ERR_CMD_COMMAND_CANCEL',
	'-1001': 'ERR_UNSPECIFIC',
	'-1002': 'ERR_UNKNOWN_METHOD',
	'-1007': 'ERR_CLOUD_FAILED',
	'-1008': 'ERR_PARAMS',
	'-1101': 'ERR_SESSION_PARAM',
	'-1201': 'ERR_QUICK_SETUP',
	'-1302': 'ERR_DEVICE_NEXT_EVENT',
	'-1401': 'ERR_FIRMWARE',
	'-1402': 'ERR_FIRMWARE_VER_ERROR',
	'-1601': 'ERR_TIME',
	'-1602': 'ERR_TIME_SYS',
	'-1603': 'ERR_TIME_SAVE',
	'-1701': 'ERR_WIRELESS',
	'-1702': 'ERR_WIRELESS_UNSUPPORTED',
	'-1801': 'ERR_SCHEDULE',
	'-1802': 'ERR_SCHEDULE_FULL',
	'-1803': 'ERR_SCHEDULE_CONFLICT',
	'-1804': 'ERR_SCHEDULE_SAVE',
	'-1805': 'ERR_SCHEDULE_INDEX',
	'-1901': 'ERR_COUNTDOWN',
	'-1902': 'ERR_COUNTDOWN_CONFLICT',
	'-1903': 'ERR_COUNTDOWN_SAVE',
	'-2001': 'ERR_ANTITHEFT',
	'-2002': 'ERR_ANTITHEFT_CONFLICT',
	'-2003': 'ERR_ANTITHEFT_SAVE',
	'-2201': 'ERR_STAT',
	'-2202': 'ERR_STAT_SAVE',
	'-2301': 'ERR_DST',
	'-2302': 'ERR_DST_SAVE'
}

class P100():
	def __init__(self,ip:str,email:str,password:str):
		self.ipAddress = ip
		self.terminalUUID = str(uuid.uuid4())
		self.errorCodes = ERROR_CODES
		self.email = email
		self.password = password
		self.encodeCredentials(email,password)
		self.createKeyPair()

	def encodeCredentials(self,email:str,password:str):
		self.encodedPassword = cipher.TpLinkCipher.mime_encoder(password.encode("utf-8"))
		
		self.encodedEmail = self.shaDigestUsername(email)
		self.encodedEmail = cipher.TpLinkCipher.mime_encoder(self.encodedEmail.encode("utf-8"))

	def createKeyPair(self):
		keys = RSA.generate(1024)
		self.privateKey = keys.exportKey("PEM")
		self.publicKey = keys.publickey().exportKey("PEM")

	def decodeHandshakeKey(self, key):
		decode: bytes = b64decode(key.encode("UTF-8"))
		decode2: bytes = self.privateKey

		pkcs1 = PKCS1_v1_5.new(RSA.importKey(decode2))
		do_final = pkcs1.decrypt(decode, None)
		if do_final is None:
			raise ValueError("Decryption failed!")

		b_arr:bytearray = bytearray()
		b_arr2:bytearray = bytearray()

		for i in range(0, 16):
			b_arr.insert(i, do_final[i])
		for i in range(0, 16):
			b_arr2.insert(i, do_final[i + 16])

		return cipher.TpLinkCipher(b_arr, b_arr2)

	def shaDigestUsername(self,data:str):
		b_arr = data.encode("UTF-8")
		digest = hashlib.sha1(b_arr).digest()

		sb = ""
		for i in range(0, len(digest)):
			b = digest[i]
			hex_string = hex(b & 255).replace("0x", "")
			if len(hex_string) == 1:
				sb += "0"
				sb += hex_string
			else:
				sb += hex_string
		
		return sb
	
	def handshake(self):
		URL = f"http://{self.ipAddress}/app"
		Payload = {
			"method":"handshake",
			"params":{
				"key": self.publicKey.decode("utf-8"),
				"requestTimeMils": int(round(time.time() * 1000))
			}
		}

		r = requests.post(URL, json=Payload, timeout=2)

		encryptedKey = r.json()["result"]["key"]
		self.tpLinkCipher = self.decodeHandshakeKey(encryptedKey)

		try:
			self.cookie = r.headers["Set-Cookie"][:-13]

		except:
			errorCode = r.json()["error_code"]
			errorMessage = self.errorCodes[str(errorCode)]
			raise Exception(f"Error Code: {errorCode}, {errorMessage}")

	def login(self):
		URL = f"http://{self.ipAddress}/app"
		Payload = {
			"method":"login_device",
			"params":{
				"username": self.encodedEmail,
				"password": self.encodedPassword
			},
			"requestTimeMils": int(round(time.time() * 1000)),
		}
		headers = {
			"Cookie": self.cookie
		}

		EncryptedPayload = self.tpLinkCipher.encrypt(json.dumps(Payload))

		SecurePassthroughPayload = {
			"method":"securePassthrough",
			"params":{
				"request": EncryptedPayload
			}
		}

		r = requests.post(URL, json=SecurePassthroughPayload, headers=headers, timeout=2)

		decryptedResponse = self.tpLinkCipher.decrypt(r.json()["result"]["response"])

		try:
			self.token = ast.literal_eval(decryptedResponse)["result"]["token"]
		except:
			errorCode = ast.literal_eval(decryptedResponse)["error_code"]
			errorMessage = self.errorCodes[str(errorCode)]
			raise Exception(f"Error Code: {errorCode}, {errorMessage}")
	
	def turnOn(self):
		URL = f"http://{self.ipAddress}/app?token={self.token}"
		Payload = {
			"method": "set_device_info",
			"params":{
				"device_on": True
			},
			"requestTimeMils": int(round(time.time() * 1000)),
			"terminalUUID": self.terminalUUID
		}

		headers = {
			"Cookie": self.cookie
		}

		EncryptedPayload = self.tpLinkCipher.encrypt(json.dumps(Payload))

		SecurePassthroughPayload = {
			"method": "securePassthrough",
			"params": {
				"request": EncryptedPayload
			}
		}

		r = requests.post(URL, json=SecurePassthroughPayload, headers=headers, timeout=2)

		decryptedResponse = self.tpLinkCipher.decrypt(r.json()["result"]["response"])

		if ast.literal_eval(decryptedResponse)["error_code"] != 0:
			errorCode = ast.literal_eval(decryptedResponse)["error_code"]
			errorMessage = self.errorCodes[str(errorCode)]
			raise Exception(f"Error Code: {errorCode}, {errorMessage}")

	def turnOff(self):
		URL = f"http://{self.ipAddress}/app?token={self.token}"
		Payload = {
			"method": "set_device_info",
			"params":{
				"device_on": False
			},
			"requestTimeMils": int(round(time.time() * 1000)),
			"terminalUUID": self.terminalUUID
		}

		headers = {
			"Cookie": self.cookie
		}

		EncryptedPayload = self.tpLinkCipher.encrypt(json.dumps(Payload))

		SecurePassthroughPayload = {
			"method": "securePassthrough",
			"params":{
				"request": EncryptedPayload
			}
		}

		r = requests.post(URL, json=SecurePassthroughPayload, headers=headers, timeout=2)

		decryptedResponse = self.tpLinkCipher.decrypt(r.json()["result"]["response"])

		if ast.literal_eval(decryptedResponse)["error_code"] != 0:
			errorCode = ast.literal_eval(decryptedResponse)["error_code"]
			errorMessage = self.errorCodes[str(errorCode)]
			raise Exception(f"Error Code: {errorCode}, {errorMessage}")

	def getDeviceInfo(self):
		URL = f"http://{self.ipAddress}/app?token={self.token}"
		Payload = {
			"method": "get_device_info",
			"requestTimeMils": int(round(time.time() * 1000)),
		}

		headers = {
			"Cookie": self.cookie
		}

		EncryptedPayload = self.tpLinkCipher.encrypt(json.dumps(Payload))

		SecurePassthroughPayload = {
			"method":"securePassthrough",
			"params":{
				"request": EncryptedPayload
			}
		}

		r = requests.post(URL, json=SecurePassthroughPayload, headers=headers)
		decryptedResponse = self.tpLinkCipher.decrypt(r.json()["result"]["response"])

		return json.loads(decryptedResponse)

	def getDeviceName(self):
		self.handshake()
		self.login()
		data = self.getDeviceInfo()

		if data["error_code"] != 0:
			errorCode = ast.literal_eval(decryptedResponse)["error_code"]
			errorMessage = self.errorCodes[str(errorCode)]
			raise Exception(f"Error Code: {errorCode}, {errorMessage}")
		else:
			encodedName = data["result"]["nickname"]
			name = b64decode(encodedName)
			return name.decode("utf-8")