from base58 import b58encode,b58decode # for Bitcoin encoding
import hashlib # for Bitcoin hashing

from library import Account,priv_to_pub,pub_to_pub
################ Bitcoin tools ##############
bitcoin_wifprefix=0x80
bitcoin_addrprefix=0x00


def hash256(x): return hashlib.sha256(x).digest()

def doublehash(x) : return hash256(hash256(x))

def ripemd160(x): return hashlib.new('ripemd160',data=x).digest()

def hash160(x) : return ripemd160(hash256(x))

def wif_to_priv(wif,compressed=True):
    pkeychecked = b58decode(wif).decode("utf-8") # convert to base58
    
    # remove firt byte (network flag) 
    # and last 4 bytes (checksum) 
    # or last 5 bytes for compressed because of the compressed byte flag
    return pkeychecked[1:-5] if compressed else pkeychecked[1:-4]

class BitcoinAccount(Account):
    network_wifprefix=bitcoin_wifprefix
    network_addrprefix=bitcoin_addrprefix
    
    def __init__(self,private=None):
        super().__init__(private)

    @classmethod
    def fromwif(cls, wif):
        return cls(wif_to_priv(wif))
        
    
    def to_wif(self,compressed=True):
        s1 = bytes([self.network_wifprefix]) + self.pk
        if(compressed):
            s1+= bytes([0x01]) # add compressed flag byte
        checksum = doublehash(s1)[:4] # first 4 bytes = checksum
        wif = s1 + checksum
        return b58encode(wif).decode('utf8')

    def to_pub(self,compressed=True):
        public = priv_to_pub(self.pk,compressed)
        return public

    def to_P2PKH(self,compressed=True):
        pub = self.to_pub(compressed=compressed)
        encrypted_pub = bytes([self.network_addrprefix]) + hash160(pub)
        check = doublehash(encrypted_pub)
        checksum = check[:4]
        address = encrypted_pub + checksum
        return b58encode(address).decode('utf8')

    def to_address(self,compressed=True):
        return self.to_P2PKH(compressed=compressed)

    def __repr__(self, compressed=True):
        string_val = "WIF: " + str(self.to_wif(compressed)) + "\n" + \
            "Address: " + self.to_address(compressed)
        return string_val


def gen_wif(compressed=True): 
    B = BitcoinAccount()
    return B.to_wif(compressed=compressed)

def wif_uncompressed_to_compressed(self,wif):
    priv = wif_to_priv(wif,compressed=False)
    B = BitcoinAccount(priv)
    return B.to_wif(compressed=True)

def wif_compressed_to_uncompressed(self,wif):
    priv = wif_to_priv(wif,compressed=True)
    B = BitcoinAccount(priv)
    return B.to_wif(priv,compressed=False)

def pub_uncompressed_to_compressed(pub):
    return pub_to_pub(pub).format(compressed=True)

def pub_compressed_to_uncompressed(pub):
    return pub_to_pub(pub).format(compressed=False)

def test_wif_checksum(wif,compressed=True):
    pkeytested = b58decode(wif).decode("utf-8")
    checksum_to_test = pkeytested[-4:]
    pkey = pkeytested[:-4]
    checksum = doublehash(pkey)[:4] # first 4 bytes = checksum
    valid = (checksum_to_test==checksum and pkeytested[:1] \
    == bytes([self.network_wifprefix])) 
    return valid

def iswifcompressed(wif):
    return False if wif[:1]=='5' else True
    
def ispubcompressed(pub):
    return True if len(pub)==33 else False
