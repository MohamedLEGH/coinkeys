0x4c

from bitcoinkeytool import BitcoinAccount

dash_wifprefix=0xCC
dash_addrprefix=0x4c

class DashAccount(BitcoinAccount):
    network_wifprefix=dash_wifprefix
    network_addrprefix=dash_addrprefix

