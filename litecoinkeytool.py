from bitcoinkeytool import BitcoinAccount

litecoin_wifprefix=0xB0
litecoin_addrprefix=0x30

class LitecoinAccount(BitcoinAccount):
    network_wifprefix=litecoin_wifprefix
    network_addrprefix=litecoin_addrprefix

