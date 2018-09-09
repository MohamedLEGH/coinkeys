from os import urandom # Should be a good source of entropy

import hashlib # for Bitcoin hashing

import coincurve # faster than ecdsa to compute public key from private key

from base58 import b58encode,b58decode # for Bitcoin encoding

from Cryptodome.Hash import keccak # for Ethereum hashing

"""
 Low-level tools to deal with bitcoin and altcoin private key, public key
 and address
"""
################## General tools #############

def gen_private_key():
    # max value of the eliptic curve
    maxval=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    
    p = urandom(32)
    
    pint = int.from_bytes(p,'big')
    assert pint<maxval, "random number\
    should be inferior to the eliptic curve max number" # almost impossible
    assert pint>0, "random number \
    should be gretter than zero" # impossible but we check anyway
    
    return p

def priv_to_pub(key,compressed=True): return coincurve.PublicKey.from_secret(key)\
        .format(compressed=compressed)
        
def priv_to_pub_raw(key): return priv_to_pub(key,compressed=False)[1:] 

class Account:
    
    def __init__(self,private=None):
        if(private is None):
            private=gen_private_key()
        self.pk = private
    
    
################ Bitcoin tools ##############
bitcoin_wifprefix=0x80
bitcoin_addrprefix=0x00

def wif_to_priv(wif,compressed=True):
    pkeychecked = b58decode(wif) # convert to base58
    
    # remove firt byte (network flag) 
    # and last 4 bytes (checksum) 
    # or last 5 bytes for compressed because of the compressed byte flag
    return pkeychecked[1:-5] if compressed else pkeychecked[1:-4]

    def test_wif_checksum(wif,network_prefix=bitcoin_wifprefix):
        pkeychecked = b58decode(wif)
        checksum_to_test = pkeytested[-4:]
        pkey = pkeytested[:-4]
        s1 = hash256(pkey)
        s2 = hash256(s1)
        checksum = s1[:4] # first 4 bytes = checksum
        valid = (checksum_to_test==checksum and pkeychecked[:1] \
        == bytes([network_prefix])) 
        return valid

"""
Utilities for Bitcoin

    def gen_wif(compressed=True): 
        return priv_to_wif(key=self.pk,compressed=compressed)

    def wif_uncompressed_to_compressed(self,wif,network_prefix=\
    network_wifprefix):
        priv = wif_to_priv(wif,compressed=False)
        return priv_to_wif(priv,network_prefix=network_prefix,compressed=True)

    def wif_compressed_to_uncompressed(self,wif,network_prefix\
    =network_wifprefix):
        priv = wif_to_priv(wif,compressed=True)
        return priv_to_wif(priv,network_prefix=network_prefix,compressed=False)

    def pub_uncompressed_to_compressed(self,pub):
        return coincurve.PublicKey(pub).format(compressed=True)

    def pub_compressed_to_uncompressed(self,pub):
        return coincurve.PublicKey(pub).format(compressed=False)

"""


def hash160(x): return hashlib.new('ripemd160',data=x).digest()

def hash256(x): return hashlib.sha256(x).digest()

class BitcoinAccount(Account):
    network_wifprefix=bitcoin_wifprefix
    network_addrprefix=bitcoin_addrprefix
    
    def __init__(self,private=None):
        super().__init__(private)
        
    
    def to_wif(self,network_prefix=network_wifprefix,compressed=True):
        s1 = bytes([network_prefix]) + self.pk
        if(compressed):
            s1+= bytes([0x01]) # add compressed flag byte
        s2 = hash256(s1)
        s3 = hash256(s2)
        checksum = s3[:4] # first 4 bytes = checksum
        wif = s1 + checksum
        return b58encode(wif)

    def to_pub(self,key,compressed=True):
        public = priv_to_pub(key,compressed)
        return public

    def to_P2PKH(self,network_prefix=network_addrprefix,compressed=True):
        pub = self.to_pub(self.pk,compressed=compressed)
        encrypted_pub = bytes([network_prefix]) + hash160(hash256(pub))
        check = hash256(hash256(encrypted_pub))
        checksum = check[:4]
        address = encrypted_pub + checksum
        return b58encode(address)

    def to_address(self,network_prefix=network_addrprefix,compressed=True):
        return self.to_P2PKH(network_prefix=network_prefix,compressed=compressed)
############## Ethereum tools ##############

def keccak256(x): return keccak.new(digest_bits=256,data=x).digest()

def checksum_encode(addr): # Takes a 20-byte binary address as input
    address = addr.lower().replace('0x', '')
    hashaddress = keccak256(address.encode('utf-8')).hex()
    ret = ''
    for i in range(len(address)):
        if (int(hashaddress[i], 16) >= 8):
            ret += address[i].upper()
        else: 
            ret += address[i]
    return '0x' + ret

class EthereumAccount(Account):
    def __init__(self,private=None):
        super().__init__(private)
        self.private_key = self.pk.hex()

    def to_pub(self):
        return priv_to_pub_raw(self.pk)

    def to_address(self,checksum=True):
        address = '0x'+ keccak256(self.to_pub())[-20:].hex()
        if(checksum):
            address = checksum_encode(address)
        return address
    
    
    
    
    
    
