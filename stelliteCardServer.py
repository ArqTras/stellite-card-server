from flask import Flask
from flask import json
from flask import request
from flask import render_template
from flask import redirect
from flask import flash
from flask import session
import json

################################################################################### SERVER CODES	

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Hash import SHA
from Crypto.Hash import SHA256
from Crypto import Random
from base64 import b64decode
import ctypes
import base64
import array
import struct
import collections
import pymongo
from pymongo import MongoClient
	
compare = lambda x, y: collections.Counter(x) == collections.Counter(y)	

# KEY PARAMETER
n = [-70, -101, -25, 125, -61, -1, 64, -63, 43, 102, 111, 70, 32, -88, -18, 103, -41, -111, -39, 19, -89, -44, -125, 126, 111, -23, 12, 50, 111, -50, -61, -9, -84, 108, 86, -65, 108, -41, -47, -38, -7, 101, -41, -44, 7, -70, -7, 48, 53, -103, 54, 99, 65, -71, -78, 80, -27, -62, -96, 126, -108, -85, -48, -115, -50, 124, -121, -13, -119, -96, -126, 100, 65, -78, 13, -79, -109, 89, -12, -46, 5, 124, 72, 44, -56, -18, 111, -84, 9, -9, -21, 80, 61, -14, 57, -107, 80, -102, -37, 107, 78, -35, -121, -108, -71, 41, 65, -109, 6, 86, -112, 63, 9, -77, -108, -71, 33, 82, -46, -28, 122, -44, -59, 35, -92, 81, -28, -43, -17, -98, -73, 30, 79, -50, -99, 48, -22, 77, 14, -40, 25, 65, 3, 68, -110, -74, 110, 98, -89, 77, -121, -79, 111, -61, -104, -98, -115, -112, -28, -36, -26, -65, 72, -40, -127, 115, 29, 76, 126, 52, -56, 116, -62, 41, 85, 65, 81, 22, -36, -31, -39, 101, 127, 106, 70, -84, -36, 20, 6, 99, -68, -91, -74, 125, -57, 15, -21, -16, 76, 78, -105, 16, 36, -39, -2, -45, 38, -98, -64, -107, -42, -87, 60, -15, -45, -61, 54, -84, 89, -90, 0, -51, 0, -64, 82, 125, 46, 72, 106, -71, 52, -75, -80, 16, 113, 52, 104, 110, 40, -7, -71, 73, 80, -107, 121, 96, -100, -48, -11, 67, 28, 112, 101, 109, 82, -25]
e = 65537
d = [-72, -51, -61, 48, -102, -43, 3, -59, 9, -3, 20, -1, -25, 66, 69, 112, 19, 93, -66, 20, 40, 38, 94, -34, -19, 103, 103, -117, -33, -116, 110, 40, -82, -38, 80, 2, -99, -127, 18, -76, 0, 63, 42, -62, 49, -79, -86, 44, 99, 56, 75, 83, 122, -8, -77, 46, 72, -116, 57, -77, -127, -6, -79, -68, 110, 28, -121, -22, -40, -122, 91, -5, 123, -48, 32, -99, -106, -89, 4, -68, -91, 112, 18, 110, 63, -61, 90, 86, -113, 60, -74, 14, -82, 122, 95, 42, -113, 59, -3, 70, -59, 64, -64, -113, -71, -37, -80, -76, 49, 23, -77, 28, -86, -73, -20, -10, 118, -104, -10, -128, 13, 96, -1, -89, 47, -119, 102, -52, 0, -36, -126, 74, 72, -26, 63, 107, -123, -9, 118, 37, -95, 61, 5, 55, -20, 8, -21, 54, 86, -78, -41, 44, -103, -126, -30, -36, 29, 111, 122, 11, 18, 114, 102, 94, -126, 117, 7, 106, -117, -58, 25, 126, 29, 113, 28, 107, 27, 78, 57, 70, 5, 25, 93, 8, 24, 87, 101, 4, 121, -30, -62, -100, -114, -21, -102, -76, 47, 124, 124, 65, -127, -65, 50, 28, -63, -56, 48, 127, 48, -36, -121, -109, 6, -114, 72, -96, -100, -3, 72, -62, -55, -52, 24, 6, -24, 1, -113, 50, 116, 68, 74, 71, -70, -8, 14, -96, 121, 10, -98, 92, -4, -119, -55, 112, 102, 54, 73, 1, -20, 71, -113, -28, -123, -8, -99, 9] 

# create key object
n = [ctypes.c_ubyte(i).value for i in n]
d = [ctypes.c_ubyte(i).value for i in d]
n = int(''.join(format(x, '02x') for x in n),16)
d = int(''.join(format(x, '02x') for x in d),16)
priKey = RSA.construct((n, e, d)).exportKey()
pubKey = RSA.construct((n, e)).exportKey()
private_key = RSA.import_key(priKey)
public_key = RSA.import_key(pubKey)
cipher_rsa_pri = PKCS1_v1_5.new(private_key)

#########################  MONGODB ACCESS
db_client = MongoClient('localhost',27017)
db_db = db_client.xtldb
db_xtlcard = db_db.xtlcard

def  verify_transactions_first_stage(cipherTxs):
	dsize = SHA.digest_size
	sentinel = Random.new().read(15+dsize)	
	
	userCredentials = None
	userHash = None
	serverInvocationCounter = None
	balance = None
	
	# decrypt cipherd txs	
	plaintext = cipher_rsa_pri.decrypt(''.join(chr(i) for i in cipherTxs), sentinel)
	plaintext = [ord(i) for i in list(plaintext)]
	# TODO get credentials, invocation counter and balance from DB
	try:
		userDat = db_xtlcard.find_one({'cred':plaintext[69:89]})
		userHash = userDat['cred']
		balance = int(userDat['bal'])
		serverInvocationCounter = int(userDat['ic'])
	except:
		return False, json.dumps({"result":"TXS_CREDENTIAL_ERR"})	

	# Verify balance
	tx_type = plaintext[0]
	credit = [ctypes.c_ubyte(i).value for i in plaintext[1:5]]
	credit = int(''.join(format(x, '02x') for x in credit),16)
	if (balance - credit)<0:
		return False, json.dumps({"result":"TXS_BALANCE_ERR"})		
	#else:
	#	session['credit'] = credit
		
	txInfo = plaintext[0:5]
	from Crypto.Signature import pkcs1_15
	random = plaintext[89:105]
	#random = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
	random = [ctypes.c_ubyte(i).value for i in random]
	alldata = userHash + txInfo + random
	alldata = [int(i) for i in alldata]
	alldata = ''.join(chr(i) for i in alldata)
	h = SHA.new(alldata)
	signature = pkcs1_15.new(private_key).sign(h)
	signature = [ord(i) for i in list(signature)]
	
	return credit, json.dumps({"result":"TXS_SIG_OK","sig":signature})	
		
def  verify_transactions_second_stage(credit, cipherTxs):
	dsize = SHA.digest_size
	sentinel = Random.new().read(15+dsize)	
	
	# decrypt ciphered txs
	cipher_rsa_pri = PKCS1_v1_5.new(private_key)	
	plaintext = cipher_rsa_pri.decrypt(''.join(chr(i) for i in cipherTxs), sentinel)
	plaintext = [ord(i) for i in list(plaintext)]
	
	try:
		userDat = db_xtlcard.find_one({'cred':plaintext[0:20]})
		userHash = userDat['cred']
		balance = int(userDat['bal'])
		serverInvocationCounter = int(userDat['ic'])		
	except:
		return False, json.dumps({"result":"TXS_CREDENTIAL_ERR"})		

	# check TXS result
	if plaintext[20] == 1:
		return False, json.dumps({"result":"TXS_SIGNATURE_ERR","balance":"N/A"})
	else:
		pass

	invocationCounter = [ctypes.c_ubyte(i).value for i in plaintext[37:41]]
	invocationCounter = int(''.join(format(x, '02x') for x in invocationCounter),16)
			
	if (invocationCounter <= serverInvocationCounter):
		return False, json.dumps({"result":"TXS_IC_ERR","balance":"N/A"})	
	else:
		pass
		
	# execute and commit all changes	
	balance = balance - credit
	serverInvocationCounter = serverInvocationCounter + 1
	db_xtlcard.find_one_and_update({'cred':plaintext[0:20]},{'$set': {'bal': int(balance), 'ic': int(serverInvocationCounter)}})
			
	return True, json.dumps({"result":"TXS_OK","balance":str(balance)})	
	
	
app = Flask(__name__)
app.secret_key = 'yu7364hd8h7yf243tdmskjc92834mt48o}{}%^#]er[\]$#!uiyeruiewuriyw7#$@!)))234923fjsfhksjdfhksdhfkjshdkfkhdkhhjksdfhkksjdyiurywieyriuyuyeiuwyrcnew238490$%^$#$&*)'
app.config['SESSION_TYPE'] = 'redis'

@app.route('/transfer', methods = ['POST'])
def transfer():
	if request.method == 'POST':
		# get encrypted Txs data
		cipherTxsRequest = request.form['cipherTxsRequest']
		cipherTxs = json.loads(cipherTxsRequest)
		result = verify_transactions_first_stage(cipherTxs)
		session['credit'] = str(result[0]) 
		return result[1]
	else:
		# POST Error 405 Method Not Allowed
		return "Error 405 Method Not Allowed"
		
@app.route('/verify', methods = ['POST'])
def verify():
	if request.method == 'POST':
		# get encrypted Txs data
		cipherTxsRequest = request.form['cipherTxsRequest']
		cipherTxs = json.loads(cipherTxsRequest)
		credit = session.get('credit')
		result = verify_transactions_second_stage(int(credit), cipherTxs)
		return result[1]
	else:
		# POST Error 405 Method Not Allowed
		return "Error 405 Method Not Allowed"		

if __name__ == '__main__':
	app.run(debug=False,host='localhost',port=7017)
	
