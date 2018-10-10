import base58 # for Ripple encoding
import hashlib # for Ripple hashing
from os import urandom # for generator of the seed
# We use the ripple alphabet instead of the bitcoin alphabet
base58.alphabet = 'rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz'

import hashlib # for Ripple hashing

from library import Account,gen_private_key,priv_to_pub,pub_to_pub,\
curveorder,max_32bitvalue

ripple_seedprefix=0x21
ripple_addrprefix=0x00
ripple_addrprefixEd = 0xED

def hash256(x): return hashlib.sha256(x).digest()

def doublehash(x) : return hash256(hash256(x))

def ripemd160(x): return hashlib.new('ripemd160',data=x).digest()

def hash160(x) : return ripemd160(hash256(x))

def hash512(x) : return hashlib.sha512(x).digest()


def seedFromPhrase(phrase):
    return hash512(phrase.encode())[:16]

def seed_encoded(seed):
    s1  = bytes([ripple_seedprefix]) + seed
    check = doublehash(s1)
    checksum = check[:4]
    seed = s1 + checksum
    return base58.b58encode(seed)

def seed_decoded(seed_b58):
    s = base58.b58decode(seed_b58)
    return s[1:-4]

def generateSeed():
    s = urandom(16).hex() # real entropy ?
    seed = seedFromPhrase(s)
    return seed_encoded(seed)

def seed_to_rootaccount(seed,algorithm='ecdsa-secp256k1'):
    s = seed + bytes(4)
    key = hash512(s)[:32]
    p = priv_to_pub(key,algorithm=algorithm)
    return key,p

def rootaccount_to_child(root_account,index_number=0,algorithm='ecdsa-secp256k1'):
    maxval = curveorder(algorithm=algorithm)
    
    pk,publickey = root_account
    c = publickey + int.to_bytes(index_number,4,'big') + bytes(4)
    additional_key = hash512(c)[:32]
    private_key = (int.from_bytes(pk,'big') \
    + int.from_bytes(additional_key,'big')) % maxval
    p = int.to_bytes(private_key,32,'big')
    return p,priv_to_pub(p,algorithm=algorithm)
    
def pub_to_account_id(pub,network_prefix=ripple_addrprefix):
    encrypted_pub = bytes([network_prefix]) + hash160(pub)
    check = doublehash(encrypted_pub)
    checksum = check[:4]
    address = encrypted_pub + checksum
    return base58.b58encode(address)
    
class RippleAccount(Account):
    def __init__(self,private=None,algorithm='ecdsa-secp256k1'):
        if(algorithm=='ecdsa-secp256k1'):
            self.addrprefix=ripple_addrprefix
        else:
            self.addrprefix=ripple_addrprefixEd
        super().__init__(private)
        
    @classmethod
    def fromphrase(cls,phrase,index_account=0,algorithm='ecdsa-secp256k1'):
        seed = seedFromPhrase(phrase)
        root=seed_to_rootaccount(seed,algorithm=algorithm)
        ck,cp = rootaccount_to_child(root,index_number=index_account,algorithm=algorithm)
        return cls(ck,algorithm=algorithm)

    @classmethod
    def fromsecret(cls,secret,index_account=0,algorithm='ecdsa-secp256k1'):
        seed = seed_decoded(secret)
        root=seed_to_rootaccount(seed,algorithm=algorithm)
        ck,cp = rootaccount_to_child(root,index_number=index_account,algorithm=algorithm)
        return cls(ck,algorithm=algorithm)
    
    @classmethod
    def fromseed(cls,secret,index_account=0,algorithm='ecdsa-secp256k1'):
        root=seed_to_rootaccount(secret,algorithm=algorithm)
        ck,cp = rootaccount_to_child(root,index_number=index_account,algorithm=algorithm)
        return cls(ck,algorithm=algorithm)
        
        
    def to_pub(self,algorithm='ecdsa-secp256k1'):
        public = priv_to_pub(self.pk,algorithm=algorithm)
        return public
        
    def to_accountid(self,algorithm='ecdsa-secp256k1'):
        pub = self.to_pub(algorithm=algorithm)
        return pub_to_account_id(pub,network_prefix=self.addrprefix)
