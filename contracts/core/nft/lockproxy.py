OntCversion = '2.0.0'
"""
Smart contract for locking and unlocking cross chain NFT asset between Ontology and other chains
"""

from ontology.interop.System.Action import RegisterAction
from ontology.interop.System.ExecutionEngine import GetExecutingScriptHash
from ontology.interop.System.Storage import Put, GetContext, Get

# Key prefix



# Common
SelfContractAddress = GetExecutingScriptHash()


# Events 
UnlockEvent = RegisterAction("unlock", "toAssetHash", "toAddress", "amount")
LockEvent = RegisterAction("lock", "fromAssetHash", "toChainId", "toAssetHash", "fromAddress", "toAddress", "amount")

def Main(operation, args):
    pass


def init():
    pass

def lock():
    pass

def unlock():
    pass
    
