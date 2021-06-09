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
    if operation == 'init':
        return init()
    if operation == 'name':
        return name()
    if operation == 'symbol':
        return symbol()
    if operation == 'totalSupply':
        return totalSupply()
    if operation == 'balanceOf':
        assert len(args) == 1, "Invalid args length for balanceOf"
        acct = args[0]
        return balanceOf(acct)
    if operation == "tokenOf":
        # TODO: ?
        # return tokenOf()
        pass
    if operation == 'transfer':
        assert len(args) == 3, "Invalid args length for transfer"
        fromAddress = args[0]
        toAddress = args[1]
        tokenId = args[2]
        return transfer(fromAddress, toAddress, tokenId)
    if operation == 'tansferFrom':
        assert len(args) == 4, "Invalid args length for transferFrom"
        spender = args[0]
        fromAddress = args[1]
        toAddress = args[2]
        tokenId = args[3]
        return transferFrom(spender, fromAddress, toAddress, tokenId)
    if operation == 'transferMulti':
        return transferMulti(args)
    if operation == 'tokenURI':
        assert len(args) == 1, "Invalid args length for tokenURI"
        return tokenURI(args[0])
    if operation == "setTokenURI":
        assert len(args) == 2, "Invalid args length for setTokenURI"
        return setTokenURI(args[0], args[1])
    if operation == "setBaseURI":
        assert len(args) == 1, "Invalid args length for setBaseURI"
        return setBaseURI(args[0])
    if operation == "baseURI":
        return baseURI()
    if operation == "transferOwnerShip":
        assert len(args) == 1, "Invalid args length for transferOwnerShip"
        return transferOwnerShip(args[0])
    if operation == "queryTokenByID":
        assert len(args) == 1, "Invalid args length for queryTokenByID"
        return queryTokenByID(args[0])
    if operation == "queryTokenIDByIndex":
        assert len(args) == 1, "Invalid args length for queryTokenIDByIndex"
        return queryTokenIDByIndex(args[0])
    if operation == 'approve':
        assert len(args) == 3, "Invalid args length for approve"
        owner = args[0]
        spender = args[1]
        amount = args[2]
        return approve(owner, spender, amount)
    return False


def init():
    assert CheckWitness(Operator), "Invalid witness"
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
    assert CheckWitness(oldOwner), "Invalid witness"
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
    assert CheckWitness(ctx, OPERATOR_PREFIX), "Invalid witness"
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

def takeOwnership(toAddress, tokenId):
    """
    transfer the approved tokenId token to toAddress
    the invoker can be the owner or the approved account
    toAddress can be any address
    :param toAddress: the account that will be assigned as the new owner of tokenId
    :param tokenId: the tokenId token will be assigned to toAddress
    :return: True or raise exception
    """

    tokenOwner = ownerOf(tokenId)
    assert isValidAddress(toAddress)
    assert isValidAddress(tokenOwner)

    approveKey = concat(APPROVE_PREFIX, tokenId)
    approvedAcct = Get(ctx, approveKey)

    assert (CheckWitness(tokenOwner) or CheckWitness(approvedAcct)), "Invalid witness"
    Delete(ctx, approveKey)

    fromBalance = balanceOf(tokenOwner)
    toBalance = balanceOf(toAddress)

    # to avoid overflow
    assert (fromBalance >= 1 and toBalance < toBalance + 1), "Invalid account balance or overflow"
    ownerKey = concat(TOKEN_OWNER_PREFIX, tokenId)
    Put(ctx, ownerKey, toAddress)

    Put(ctx, concat(OWNER_BALANCE_PREFIX, tokenOwner), fromBalance - 1)
    Put(ctx, concat(OWNER_BALANCE_PREFIX, toAddress), toBalance + 1)

    Notify(['transfer', tokenOwner, toAddress, tokenId])
    return True

def transferFrom(spender, fromAddress, toAddress, tokenId):
    return True

def transfer(toAddress, tokenId):
    """
    transfer the token with tokenId to the toAddress
    :param toAddress: to account address
    :param tokenId: the unique token's ID, type should be ByteArray
    :return: False means failure, True means success.
    """
    tokenOwner = ownerOf(tokenId)
    assert CheckWitness(tokenOwner), "Invalid owner witness"
    assert isValidAddress(toAddress)

    ownerKey = concat(TOKEN_OWNER_PREFIX, tokenId)
    fromAcct = Get(ctx, ownerKey)

    # Check balance
    fromBalanceKey = concat(OWNER_BALANCE_PREFIX, fromAcct)
    toBalanceKey = concat(OWNER_BALANCE_PREFIX, toAddress)
    fromBalance = Get(ctx, fromBalanceKey)
    toBalance = Get(ctx, toBalanceKey)
    assert (fromBalance >= 1 and toBalance < toBalance + 1), "Invalid account balance or overflow"

    Delete(ctx, concat(APPROVE_PREFIX, tokenId))
    Put(ctx, fromBalanceKey, fromBalance - 1)
    Put(ctx, toBalanceKey, toBalance + 1)
    # set the owner of tokenID to toAcct
    Put(ctx, ownerKey, toAddress)

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


