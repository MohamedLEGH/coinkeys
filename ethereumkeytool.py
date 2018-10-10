from Cryptodome.Hash import keccak # for Ethereum hashing

from library import priv_to_pub_raw,Account
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


    def to_pub(self):
        return priv_to_pub_raw(self.pk)

    def to_address(self,checksum=True):
        address = '0x'+ keccak256(self.to_pub())[-20:].hex()
        if(checksum):
            address = checksum_encode(address)
        return address

