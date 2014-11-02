
import sys, ctypes, random
from binascii import hexlify, unhexlify
from Crypto.Hash import SHA512
from Crypto import Random
from ecdsa import *
from base58 import *
from bip32 import *

class rawtx(object):

	def __init__(self):
		super(rawtx, self).__init__()
		self.version = 1
		self.timelock = unhexlify('00000000')
		self.inputs = []
		self.outputs = []

	def decode_transaction(self, hexcode):

		# Begin decoding
		try:
			trans = unhexlify(hexcode)
		except:
			return False

		# Set initial variables
		self.version = int(hexlify(trans[:4][::-1]), 10)
		num_inputs = int(hexlify(trans[4:5]), 10)
		p = 5

		# Go through inputs
		for x in range(0, num_inputs):
			txid = trans[p:(p+32)][::-1]
			vout = int(hexlify(trans[(p+32):(p+36)][::-1]))
			script_length = int(hexlify(trans[(p+36):(p+37)]), 16)
			sigscript = trans[(p+37):(p+37+script_length)]
			p += (41 + script_length);
			sequence = trans[(p-4):p]

			self.inputs.append({
				'txid': txid, 
				'vout': vout, 
				'sigscript': sigscript, 
				'sequence': sequence
			})

		# Go through outputs
		num_outputs = int(hexlify(trans[p:(p+1)]), 10)
		p += 1
		for x in range (0, num_outputs):
			amount = int(hexlify(trans[p:(p+8)][::-1]), 16) * 1e8
			script_length = int(hexlify(trans[(p+8):(p+9)]), 16)
			script = trans[(p+9):(p+9+script_length)]
			p += (9 + script_length)

			self.outputs.append({
				'amount': amount, 
				'script': script
			})

		# Finish up
		self.timelock = trans[p:(p+4)]

	def encode_transaction(self, input_num = None):

		# Start transaction
		trans = bytearray()
		trans += ctypes.c_uint32(self.version)
		trans += ctypes.c_uint8(len(self.inputs))

		# Go through inputs
		x=0
		for item in self.inputs:
			trans += item['txid'][::-1]
			trans += ctypes.c_uint32(item['vout'])

			if input_num == None or input_num == x:
				trans += self.encode_vint(len(item['sigscript']))
				trans += item['sigscript']
			else:
				trans += unhexlify('00')

			trans += item['sequence']
			x += 1

		# Go through outputs
		trans += ctypes.c_uint8(len(self.outputs))
		for item in self.outputs:

			# Add output
			trans += ctypes.c_uint64(int(item['amount'] * 1e8))
			trans += self.encode_vint(len(item['script']))
			trans += item['script']

		# Finish encoding
		trans += self.timelock
		return trans

	def add_input(self, txid, vout, sigscript, keyindex = None, sequence = None):
		if sequence == None:
			sequence = unhexlify('ffffffff')

		self.inputs.append({
			'txid': txid, 
			'vout': vout, 
			'keyindex': keyindex, 
			'sigscript': sigscript, 
			'sequence': sequence
		})

	def add_output(self, amount, address):

		# Create script
		daddr = hexlify(b58decode(address, None))
		if daddr[:2] == 'c4' or daddr[:2] == '05':
			script = 'a914' + daddr[2:42] + '87'
		else:
			script = '76a914' + daddr[2:42] + '88ac'
		
		# Add output
		self.outputs.append({
			'amount': amount, 
			'script': unhexlify(script)
		})

	def get_vint(self, trans, p):

		if (trans[p] == 0xfd):
			print("FD")
		elif (trans[p] == 0xfe):
			print("FE")
		elif (trans[p] == 0xff):
			print("FF")
		else:
			print("VNONE")


	def set_keyindex(self, x, keyindex, private_key):
		bip = bip32()
		address = bip.key_to_address(bip.derive_child(private_key, str(keyindex)))

		self.inputs[x]['keyindex'] = str(keyindex)
		self.inputs[x]['sigscript'] = unhexlify('76a914' + hexlify(b58decode(address, None))[2:] + '88ac')

	def sign_transaction(self, private_key):

		# Go through inputs
		x = 0
		for item in self.inputs:
			hexcode = self.encode_transaction(x) + unhexlify('01000000')

			# Get child key
			bip = bip32()
			child_key = bip.derive_child(private_key, item['keyindex'])

			# Decode child key
			bip.decode_key(child_key)
			public_key = bip.private_to_public(bip.key)
			cpubkey = bip.private_to_public(bip.key, True)

			# Generate keys for signing
			pubkey = Public_key( g, g * int(hexlify(bip.key), 16) )
			privkey = Private_key(pubkey, int(hexlify(bip.key), 16))

			# Sign tx
			hash = hashlib.sha256(hashlib.sha256(hexcode).digest()).hexdigest()
			signature = privkey.sign(int(hash, 16), random.SystemRandom().randrange(1, g.order()))
			r = hex(signature.r).lstrip('0x').rstrip('L').zfill(64)
			s = hex(signature.s).lstrip('0x').rstrip('L').zfill(64)

			#print 'verifies', pubkey.verifies(int(hash, 16), signature )

			# Encode signature
			der = '30' + hexlify(ctypes.c_uint8(int((len(r) + len(s)) / 2) + 4)) + '02' + hexlify(ctypes.c_uint8(int(len(r)/2))) + r + '02' + hexlify(ctypes.c_uint8(int(len(s)/2))) + s + '01'
			item['sigscript'] = unhexlify('47' + der + hexlify(ctypes.c_uint8(len(cpubkey))))
			item['sigscript'] += cpubkey
			x += 1			

		# Finish transaction
		return hexlify(self.encode_transaction())

	def encode_vint(self, num):

		## Get vint
		if num < 253:
			res = binascii.hexlify(ctypes.c_uint8(num))
		elif num < 65535:
			res = 'fd' + binascii.hexlify(ctypes.c_uint16(num))
		elif num < 4294967295:
			res = 'fe' + binascii.hexlify(ctypes.c_uint32(num))
		else:
			res = 'ff' + binascii.hexlify(ctypes.c_uint64(num))

		# Return
		return unhexlify(res)

