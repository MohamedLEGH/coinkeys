from os import urandom # Should be a good source of entropy
import json
import coincurve # faster than ecdsa to compute public key from private key
import ed25519
"""
 Low-level tools to deal with private key, public key
 and address
"""
################## General tools #############

max_32bitvalue = 0xffffffff

def curveorder(algorithm='ecdsa-secp256k1'):
    if(algorithm=='ecdsa-secp256k1'):
        # max val of the secp256k1 eliptic curve
        maxval=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    elif(algorithm=='ed25519'):
        # max val of the ed25519 eliptic curve
        maxval = 2**252 + 27742317777372353535851937790883648493
    return maxval

def gen_private_key(algorithm='ecdsa-secp256k1'):
    # max value of the eliptic curve
    
    maxval = curveorder(algorithm=algorithm)
    p = urandom(32) # almost any 32 random bytes array is a private key
    pint = int.from_bytes(p,'big')
    
    while(pint>maxval or pint<0): # a private key cannot be zero (or below)
    # and should be lower than the maximal value of the eliptic curve
        p = urandom(32)
        pint = int.from_bytes(p,'big')
    return p

def priv_to_pub(key,compressed=True,algorithm='ecdsa-secp256k1'):
    if(algorithm=='ecdsa-secp256k1'):
        return coincurve.PublicKey.from_secret(key).format(compressed=compressed)
    elif(algorithm=='ed25519'):
        return ed25519.SigningKey(key).get_verifying_key().to_bytes()
        
        
def priv_to_pub_raw(key): # only for ecdsa-secp256k1 curve
    return priv_to_pub(key,compressed=False)[1:] 

def pub_to_pub(pub,compressed=True): 
    return coincurve.PublicKey(pub).format(compressed=compressed)

class Account:
    
    def __init__(self,private=None,algorithm='ecdsa-secp256k1'):
        if(private is None): # need to check type of input (bytes only)
            private=gen_private_key(algorithm=algorithm)
        self.pk = private
 
    @classmethod
    def fromhex(cls, hexa):  # need to check type of input (str only)
        return cls(bytes.fromhex(hexa))

    @classmethod
    def fromfile(cls, file_name):
        with open(file_name) as json_file:
            data = json.load(json_file)
            return cls.fromhex(data["private_key"])

    def private_key(self):
        return self.pk.hex()

    def to_file(self, file_name):
        key = {"private_key": self.private_key()}
        with open(file_name, 'w') as key_file:
            json.dump(key, key_file)
    
    
    def sign(self,message):
        signature = coincurve.PrivateKey(self.pk).sign(message.encode())
        return signature

