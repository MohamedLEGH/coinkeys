from os import urandom # Should be a good source of entropy

import coincurve # faster than ecdsa to compute public key from private key

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
    
    

