OntCversion = '2.0.0'
"""
Smart contract for nft asset for cross chain.
"""
from ontology.interop.System.Storage import Put, GetContext, Get, Delete
from ontology.interop.System.Runtime import CheckWitness, Notify, Serialize, Deserialize
from ontology.interop.Ontology.Runtime import Base58ToAddress
from ontology.interop.System.Action import RegisterAction
from ontology.builtins import concat

# Constant
NAME = "xx"
SYMBOL = "xx"

# Key prefix
OPERATOR_PREFIX = "Operator"
APPROVE_PREFIX = "Approve"
TOKEN_OWNER_PREFIX = "TokenOwner"
TOTAL_SUPPLY_PREFIX = "TotalSupply"
TOKEN_PREFIX = "Token"
TOKEN_INDEX_PREFIX = "TokenIndex"
OWNER_BALANCE_PREFIX = "OwnerBalance"
BASE_URI_PREFIX = "BaseURI"
TOKEN_URI_PREFIX = "TokenURI"

# Common
ctx = GetContext()

ZeroAddress = bytearray(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
Operator = Base58ToAddress("xx")

# Event
TransferOwnershipEvent = RegisterAction("transferOwnership", "oldOwner", "newOwner")
TransferEvent = RegisterAction("transfer", "from", "to", "tokenId")
ApprovalEvent = RegisterAction("approval", "from", "to", "tokenId")

def Main(operation, args):
    return True

def init():
    assert CheckWitness(Operator)
    assert len(getOwner()) == 0, "Contract already initialized"
    Put(ctx, OPERATOR_PREFIX, Operator)
    return True

def getOwner():
    """
    :return: contract owner from storage
    """
    return Get(ctx, OPERATOR_PREFIX)

def name():
    """
    :return: name of the token
    """
    return NAME

def symbol():
    """
    :return: symbol of the token
    """
    return SYMBOL

def balanceOf(owner):
    """
    :param owner:
    :return: token balance of the owner
    """
    assert isValidAddress(owner)
    return Get(ctx, concat(OWNER_BALANCE_PREFIX, owner))

def transferOwnerShip(newOwner):
    oldOwner = getOwner()
    assert CheckWitness(oldOwner)
    assert isValidAddress(newOwner)
    Put(ctx, OPERATOR_PREFIX, newOwner)
    TransferOwnershipEvent(oldOwner, newOwner)
    return True

def baseURI ():
    """
    Get Base URI from storage
    :return: base uri
    """
    return Get(ctx, BASE_URI_PREFIX)

def setBaseURI(baseURI):
    """
    Set new base uri
    :param baseURI: new base uri
    :return: True
    """
    assert (CheckWitness(ctx, OPERATOR_PREFIX))
    Put(ctx, BASE_URI_PREFIX, baseURI)
    Notify(['setBaseURI', baseURI])
    return True

def tokenExists(tokenId):
    """
    Check existence of token
    :param tokenId: token id
    :return: True if exists
    """
    if not Get(ctx, concat(TOKEN_OWNER_PREFIX, tokenId)):
        raise Exception("Token does not exist")
    return True


def tokenURI (tokenId):
    """
    Get token URI from storage
    :return: token uri
    """
    return Get(ctx, concat(TOKEN_URI_PREFIX, tokenId))

def setTokenURI(tokenId, tokenURI):
    """
    Set new uri for token
    :param tokenId: tokenId
    :param tokenURI: new token uri
    :return: True
    """
    assert tokenExists(tokenId)
    Put(ctx, concat(TOKEN_URI_PREFIX, tokenId), tokenURI)
    Notify(['setTokenURI', tokenId, tokenURI])
    return True

def approve(toAddress, tokenId):
    """
    approve the token to toAcct address, it can overwrite older approved address
    :param toAddress: to address
    :param tokenId: token id
    :return: True on success
    """
    tokenOwner = ownerOf(tokenId)
    if CheckWitness(tokenOwner) == False:
        return False
    assert isValidAddress(toAddress)

    Put(ctx, concat(APPROVE_PREFIX, tokenId), toAddress)
    Notify(['approval', tokenOwner, toAddress, tokenId])
    return True

def ownerOf(tokenId):
    """
    get the owner of the unique token with this tokenId
    :param tokenId: the tokenId should be unique and exist.
    :return: the owner address of the token with this unique tokenId
    """
    key = concat(TOKEN_OWNER_PREFIX, tokenId)
    owner = Get(ctx, key)
    if not owner:
        raise Exception('ownerOf failed!')
    return owner

def getApproved(tokenId):
    """
    get the approved address of the token
    :param tokenID:
    :return:
    """
    key = concat(APPROVE_PREFIX, tokenId)
    return Get(ctx, key)

def totalSupply():
    return Get(ctx, TOTAL_SUPPLY_PREFIX)

def transferOwnerShip(toAddress, tokenId):
    """
    transfer the approved tokenId token to toAcct
    the invoker can be the owner or the approved account
    toAcct can be any address
    :param toAddress: the account that will be assigned as the new owner of tokenId
    :param tokenId: the tokenId token will be assigned to toAcct
    :return: False or True
    """
    assert isValidAddress(toAddress)
    tokenOwner = ownerOf(tokenId)

    if not tokenOwner:
        return False
    approveKey = concat(APPROVE_PREFIX, tokenId)
    approvedAcct = Get(ctx, approveKey)

    if not CheckWitness(tokenOwner) and not CheckWitness(approvedAcct):
        return False

    Delete(ctx, approveKey)
    ownerKey = concat(TOKEN_OWNER_PREFIX, tokenId)
    Put(ctx, ownerKey, toAddress)

    fromBalance = balanceOf(tokenOwner)
    toBalance = balanceOf(toAddress)
    # to avoid overflow
    if fromBalance >= 1 and toBalance < toBalance + 1:
        Put(ctx, concat(OWNER_BALANCE_PREFIX, tokenOwner), fromBalance - 1)
        Put(ctx, concat(OWNER_BALANCE_PREFIX, toAddress), toBalance + 1)

    Notify(['transfer', tokenOwner, toAddress, tokenId])
    return True

def queryTokenIDByIndex(idx):
    """
    query tokenid by index
    :param idx: token index
    :return: tokenId
    """
    tokenId = Get(ctx, concat(TOKEN_INDEX_PREFIX, idx))
    return tokenId

def queryTokenByID(tokenId):
    """
    query token detail by tokenId
    :param tokenId: tokenId
    :return: token meta data [id, name, image, type]
    """
    token = Get(ctx, concat(TOKEN_PREFIX, tokenId))
    info = Deserialize(token)
    id = info['ID']
    name = info['Name']
    image = info['Image']
    type = info['Type']
    return [id, name, image, type]

def transfer(toAddress, tokenId):
    """
    transfer the token with tokenId to the toAddress
    :param toAddress: to account address
    :param tokenId: the unique token's ID, type should be ByteArray
    :return: False means failure, True means success.
    """
    tokenOwner = ownerOf(tokenId)
    if CheckWitness(tokenOwner) == False:
        return False
    assert isValidAddress(toAddress)

    ownerKey = concat(TOKEN_OWNER_PREFIX, tokenId)
    fromAcct = Get(ctx, ownerKey)
    balanceKey = concat(OWNER_BALANCE_PREFIX, fromAcct)
    fromBalance = Get(ctx, balanceKey)
    if fromBalance >= 1:
        # decrease fromAccount token balance
        Put(ctx, balanceKey, fromBalance - 1)
    else:
        raise Exception('fromBalance error')
    # set the owner of tokenID to toAcct
    Put(ctx, ownerKey, toAddress)
    # increase toAccount token balance
    balanceKey = concat(OWNER_BALANCE_PREFIX, toAddress)
    Put(ctx, balanceKey, balanceOf(toAddress) + 1)
    Delete(ctx, concat(APPROVE_PREFIX, tokenId))
    Notify(['transfer', fromAcct, toAddress, tokenId])
    return True

def transferMulti(args):
    """
    multi transfer
    :param args:[[toAccount1, tokenID1],[toAccount2, tokenID2]]
    :return: True or raise exception
    """
    assert len(args) > 0, "No transfer payload specified"
    for p in args:
        assert len(p) == 2, 'transferMulti failed - input error!'
        assert transfer(p[0], p[1])
    return True

def isValidAddress(address):
    """
    Validate address, check length, and not zero address
    :param address: address
    :return: True or raise exception
    """
    assert (len(address) == 20 and address != ZeroAddress), "Invalid address"
    return True


