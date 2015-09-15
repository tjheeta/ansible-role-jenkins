#!/usr/bin/env python

import re
import sys
import base64
from hashlib import sha256
from hashlib import md5
from binascii import hexlify, unhexlify
from Crypto.Cipher import AES

MAGIC = "::::MAGIC::::"

def usage():
  print "./encrypt.py <master.key> <hudson.util.Secret> <api_key>"
  sys.exit(0)

def main():
  if len(sys.argv) != 4:
    usage()

  master_key = open(sys.argv[1]).read()
  hudson_secret_key = open(sys.argv[2]).read()

  hashed_master_key = sha256(master_key).digest()[:16]
  o = AES.new(hashed_master_key, AES.MODE_ECB)
  x = o.decrypt(hudson_secret_key)
  assert MAGIC in x

  k = x[:-16] 
  k = k[:16]

  new_api_key = sys.argv[3] + MAGIC + ""

  o = AES.new(k, AES.MODE_ECB)
  x = o.encrypt(new_api_key)
  p = base64.encodestring(x).rstrip()

  print p


if __name__ == '__main__':
  main()
