#!/usr/bin/env python3

import os
import hashlib
from base64 import b64encode
from argparse import ArgumentParser

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend


class AES:

	def __init__(self, password, iv): 
		self.key = hashlib.sha256(password.encode()).digest()
		self.iv = iv

	def encrypt(self, raw):
		backend = default_backend()
		padder = padding.PKCS7(128).padder()
		raw = padder.update(raw) + padder.finalize()
		cipher = Cipher(algorithms.AES(self.key), modes.CBC(self.iv), backend=backend)
		encryptor = cipher.encryptor()
		return self.iv + encryptor.update(raw) + encryptor.finalize()


class XOR:

	def __init__(self, key):
		self.key = key

	def encrypt(self, raw):
		output = ''
		for i in range(len(raw)):
			c = raw[i]
			k = self.key[i % len(self.key)]
			output += chr(ord(c) ^ ord(k))

		return output


def parse_args():
	parser = ArgumentParser()
	parser.add_argument('shellcode_bin', action='store', type=str)
	parser.add_argument('-p', '--password', action='store', type=str, required=True)
	parser.add_argument('-a', '--algorithm', action='store', type=str, default='aes', choices=['aes', 'xor'])
	parser.add_argument('-o', '--output', action='store', type=str)
	parser.add_argument('--base64', action='store_true', default=False)
	return parser.parse_args()


if __name__ == '__main__':
	args = parse_args()

	with open(args.shellcode_bin, 'rb') as fd:
		shellcode = fd.read()

	if args.algorithm == 'aes':
		iv = os.urandom(16)
		ctx = AES(args.password, iv)
		enc = ctx.encrypt(shellcode)
	elif args.algorithm == 'xor':
		ctx = XOR(args.password)

	enc = ctx.encrypt(shellcode)

	if args.base64:
		print(b64encode(enc).decode())
	else:
		with open(args.output, 'wb') as fd:
			fd.write(enc)
		print(f'[+] Encrypted shellcode file: {args.output}')
