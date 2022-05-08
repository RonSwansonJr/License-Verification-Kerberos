import Crypto
from Crypto.PublicKey import RSA
from Crypto import Random
import base64
import math
import json
class ticket:
    def __init__(self,id,issued_time,lifetime,main_server=None):
        self.ID=id
        self.issue=issued_time
        self.lifetime=lifetime
        self.main_server=main_server
    
    def toJSON(self):
        return json.dumps(self, default=lambda o: o.__dict__, 
            sort_keys=True, indent=4)
            

# def encrypt(message, pub_key):
#     #RSA encryption protocol according to PKCS#1 OAEP
#     cipher = PKCS1_OAEP.new(pub_key)
#     return binascii.hexlify(cipher.encrypt(message))

# def decrypt(ciphertext, priv_key):
#     #RSA encryption protocol according to PKCS#1 OAEP
#     cipher = PKCS1_OAEP.new(priv_key)
#     return binascii.hexlify(cipher.decrypt(ciphertext))

def encrypt(rsa_publickey,plain_text):
    rsa_publickey = RSA.importKey(rsa_publickey)
    cipher_text=rsa_publickey.encrypt(plain_text,32)[0]
    b64cipher=base64.b64encode(cipher_text)
    return b64cipher

def decrypt(rsa_privatekey,b64cipher):
    rsa_privatekey = RSA.importKey(rsa_privatekey)
    decoded_ciphertext = base64.b64decode(b64cipher)
    plaintext = rsa_privatekey.decrypt(decoded_ciphertext)
    return plaintext

def sign(privatekey,data):
    privatekey = RSA.importKey(privatekey)
    return base64.b64encode(str((privatekey.sign(data,''))[0]).encode())

def verify(publickey,data,sign):
    publickey = RSA.importKey(publickey)
    return publickey.verify(data,(int(base64.b64decode(sign)),))

# def encrypt(value,key,priv=False):
#     key = RSA.importKey(key.decode('utf8'))
#     temp=int.from_bytes(value, byteorder='big')
#     if not priv:
#         cipher=pow(temp,key.e,key.n)
#     else:
#         cipher = pow(temp,key.d,key.n)
#     byte_len = int(math.ceil(cipher.bit_length() / 8))
#     return cipher.to_bytes(byte_len,byteorder='big')

# def decrypt(value,key2,priv=False):
#     key2 = RSA.importKey(key2.decode('utf8')) 
#     cipher = int.from_bytes(value, byteorder='big') 
#     if priv:
#         message = pow(cipher,key2.d,key2.n)
#     else:
#         message = pow(cipher,key2.e,key2.n)
#     byte_len = int(math.ceil(message.bit_length() / 8))
#     return message.to_bytes(byte_len,byteorder='big').decode('utf8')