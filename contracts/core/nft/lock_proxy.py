OntCversion = '2.0.0'
"""
Smart contract for locking and unlocking cross chain NFT asset between Ontology and other chains
"""
from ontology.interop.Ontology.Native import Invoke
from ontology.interop.System.Action import RegisterAction
from ontology.interop.System.ExecutionEngine import GetExecutingScriptHash, GetCallingScriptHash
from ontology.interop.System.Storage import Put, GetContext, Get
from ontology.interop.Ontology.Runtime import Base58ToAddress
from ontology.interop.System.Runtime import CheckWitness, Notify, Serialize, Deserialize
from ontology.builtins import concat, state, append, remove
from ontology.interop.System.App import DynamicAppCall

# Key prefix
OPERATOR_PREFIX = "Operator"
PROXY_HASH_PREFIX = "ProxyHash"
ASSET_HASH_PREFIX = "AssetHash"    # target asset hash
ASSET_LIST_PREFIX = "AssetList"    # from asset hash list

# Common
ctx = GetContext()
SelfContractAddress = GetExecutingScriptHash()

Operator = Base58ToAddress("xxx")
CrossChainContractAddress = bytearray(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x09')
ZeroAddress = bytearray(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
ONTAddress = bytearray(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01')
ONGAddress = bytearray(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02')

# Events
UnlockEvent = RegisterAction("unlock", "toAssetHash", "toAddress", "amount")
LockEvent = RegisterAction("lock", "fromAssetHash", "fromAddress", "toAssetHash", "toAddress", "toChainId", "tokenId")
TransferOperatorEvent = RegisterAction("transferOperator", "oldOperator", "newOperator")


def Main(operation, args):
    if operation == "init":
        return init()
    if operation == "bindProxyHash":
        assert len(args) == 2, "Invalid args length for bindProxyHash"
        toChainId = args[0]
        targetProxyHash = args[1]
        return bindProxyHash(toChainId, targetProxyHash)
    if operation == "bindAssetHash":
        assert len(args) == 3, "Invalid args length for bindAssetHash"
        fromAssetHash = args[0]
        toChainId = args[1]
        toAssetHash = args[2]
        return bindAssetHash(fromAssetHash, toChainId, toAssetHash)
    if operation == "getProxyHash":
        assert len(args) == 1, "Invalid args length for getProxyHash"
        toChainId = args[0]
        return getProxyHash(toChainId)
    if operation == "getAssetHash":
        assert len(args) == 2, "Invalid args length for getAssetHash"
        fromAssetHash = args[0]
        toChainId = args[1]
        return getAssetHash(fromAssetHash, toChainId)
    if operation == "unlock":
        assert len(args) == 3, "Invalid args length for unlock"
        params = args[0]
        fromContractAddr = args[1]
        fromChainId = args[2]
        return unlock(params, fromContractAddr, fromChainId)
    if operation == "getBalanceFor":
        assert len(args)  == 1, "Invalid args length for getBalanceFor"
        return getBalanceFor(args[0])
    if operation == "removeFromAssetHash":
        assert len(args) == 1, "Invalid args length for removeFromAssetHash"
        index = args[0]
        return removeFromAssetHash(index)
    if operation == "addFromAssetHash":
        assert len(args) == 1, "Invalid args length for addFromAssetHash"
        fromAssetHash = args[0]
        return addFromAssetHash(fromAssetHash)
    return False


def init():
    """
    Set initial contract operator
    """
    assert len(Get(ctx, OPERATOR_PREFIX)) == 0, "Contract already initialized"
    Put(ctx, OPERATOR_PREFIX, Operator)
    return True

def transferOperator(newOperator):
    """
    Transfer operator to new owner
    :param newOperator: new operator
    :return: True
    """
    oldOperator = Get(ctx, OPERATOR_PREFIX)
    assert CheckWitness(oldOperator), "Invalid witness"
    assert isValidAddress(newOperator)
    Put(ctx, OPERATOR_PREFIX, newOperator)
    TransferOperatorEvent(oldOperator, newOperator)
    return True

def getBalanceFor(assetHash):
    """
    Get contract balance of asset
    :param assetHash: asset hash
    :return: asset balance
    """
    if assetHash == ONGAddress or assetHash == ONTAddress:
        return Invoke(0, assetHash, "balanceOf", SelfContractAddress)
    else:
        return DynamicAppCall(assetHash, "balanceOf", [SelfContractAddress])

def addFromAssetHash(fromAssetHash):
    """
    Save from asset hash into asset hash list if not yet
    :param fromAssetHash: source asset hash
    :return: True
    """
    assert CheckWitness(Get(ctx, OPERATOR_PREFIX)), "Invalid contract operator"

    data = Get(ctx, ASSET_LIST_PREFIX)
    if not data:
        assetList = []
    else:
        assetList = Deserialize(data)
    if fromAssetHash not in assetList:
        assetList.append(fromAssetHash)
        Put(ctx, ASSET_LIST_PREFIX, Serialize(assetList))
        Notify(["addFromAssetHash", fromAssetHash])
    return True

def removeFromAssetHash(assetHash):
    """
    Remove asset hash from asset hash list
    :param assetHash: source asset hash
    :return: True
    """
    assert CheckWitness(Get(ctx, OPERATOR_PREFIX)), "Invalid contract operator"

    data = Get(ctx, ASSET_LIST_PREFIX)
    if not data:
        return True
    assetList = Deserialize(data)
    if assetHash in assetList:
        assetHash.remove(assetHash)
        Put(ctx, ASSET_LIST_PREFIX, Serialize(assetList))
        Notify(["removeFromAssetHash", assetHash])
    return True

def getFromAssetHashList():
    """
    Fetch fromAsset hash list
    :return: list of fromAssetHash
    """
    data = Get(ctx, ASSET_LIST_PREFIX)
    if not data:
        return []
    return Deserialize(data)

def bindAssetHash(fromAssetHash, toChainId, toAssetHash):
    """
    Bind target asset hash
    :param fromAssetHash: Source asset hash
    :param toChainId: targetChainId
    :param toAssetHash: target asset hash
    :return: True
    """
    assert CheckWitness(Get(ctx, OPERATOR_PREFIX)), "Invalid contract operator"
    assert addFromAssetHash(fromAssetHash)
    Put(ctx, concat(ASSET_HASH_PREFIX, concat(fromAssetHash, toChainId)), toAssetHash)
    curBalance = getBalanceFor(fromAssetHash)
    Notify(["bindAssetHash", fromAssetHash, toChainId, toAssetHash, curBalance])
    return True

def getAssetHash(fromAssetHash, toChainId):
    """
    Get target asset hash with from asset hash and target chain id
    :param fromAssetHash: Source asset hash
    :param toChainId: targetChainId
    :return: target asset hash
    """
    return Get(ctx, concat(ASSET_HASH_PREFIX, concat(fromAssetHash, toChainId)))

def bindProxyHash(chainId, targetProxyHash):
    """
    Bind chain id with proxy hash
    :param toChainId: chain id
    :param targetProxyHash: proxy hash
    :return: True
    """
    assert CheckWitness(ctx, OPERATOR_PREFIX), "Invalid operator"
    Put(ctx, concat(PROXY_HASH_PREFIX, chainId), targetProxyHash)
    return True

def getProxyHash(chainId):
    """
    Get bound chain proxy hash from context
    :param chainId: chain id
    :return: chain bound proxy hash
    """
    return Get(ctx, concat(PROXY_HASH_PREFIX, chainId))


def isValidAddress(address):
    """
    Validate address, check length, and not zero address
    :param address: address
    :return: True or raise exception
    """
    assert (len(address) == 20 and address != ZeroAddress), "Invalid address"
    return True


def lock(fromAddress, tokenId, params):
    """
    On erc721 asset received, trigger the cross chain contract call.
    :param fromAddress: from address
    :pram tokenId: token id
    :param params: argument list [assetHash, address, tokenId, tokenURI]
    :return: True or raise exception
    """
    fromAssetHash = GetCallingScriptHash()
    assert CheckWitness(fromAddress), "Invalid witness"
    toAddress, toChainId = _deserializeCallData(params)
    assert isValidAddress(toAddress)

    toAssetHash = getAssetHash(fromAssetHash, toChainId)
    owner = DynamicAppCall(fromAssetHash, "ownerOf", tokenId)
    assert (owner == SelfContractAddress), "wrong owner for this token ID"

    tokenURI = DynamicAppCall(fromAssetHash, "UriOf", tokenId)
    toProxyHash = getProxyHash(toChainId)
    txData = _serializeArgs([toAssetHash, toAddress, tokenId, tokenURI])
    args = state(toChainId, toProxyHash, "unlock", txData)

    # Lock the nft token
    res = DynamicAppCall(fromAssetHash, "transfer", [SelfContractAddress, tokenId])
    assert (res and res == b'\x01'), "Asset transfer failed"

    res = Invoke(0, CrossChainContractAddress, "createCrossChainTx", args)
    assert (res and res == b'\x01'), "createCrossChainTx failed"

    Notify(["lock", fromAssetHash, fromAddress, toProxyHash, toAddress, toChainId, tokenId])
    LockEvent(fromAssetHash, fromAddress, toProxyHash, toAddress, toChainId, tokenId)
    return True


def unlock(params, fromContractAddr, fromChainId):
    """
    Unlock nft asset from proxy lock to finish the cross chain transaction
    :param params: packed argument list [assetHash, address, tokenId, tokenURI]
    :param fromContractAddr: the invoker contract address
    :param: fromChainId: source chain id on poly network
    :returns:
    """
    assert CheckWitness(CrossChainContractAddress), "Invalid witness"
    assert getProxyHash(fromChainId) == fromContractAddr, "Invalid chain proxy contract address"

    assetHash, address, tokenId, tokenURI = _deserializeArgs(params)
    assert isValidAddress(assetHash)
    assert isValidAddress(address)

    owner = DynamicAppCall(assetHash, "ownerOf", tokenId)
    if owner != ZeroAddress:
        assert owner == SelfContractAddress, "Asset unlock failed for invalid owner"
        res = DynamicAppCall(assetHash, "transfer", [address, tokenId])
        assert (res and res == b'\x01'), "transfer failed"
    else:
        res = DynamicAppCall(assetHash, "mintWithURI", [address, tokenId, tokenURI])
        assert (res and res == b'\x01'), "mintWithURI failed"

    UnlockEvent(assetHash, address, tokenId)
    return True

def _serializeCallData(args):
    assert len(args) == 2, "Invalid args length"
    # address
    buf = WriteVarBytes(args[0], None)
    # chain Id
    buf = WriteUint64(args[2], buf)

    return buf

def _deserializeCallData(buf):
    offset = 0
    res = NextVarBytes(buf, offset)
    address = res[0]

    res = NextUint64(buf, res[1])
    chainId = res[0]
    return [address, chainId]


def _serializeArgs(args):
    assert len(args) == 4, "Invalid args length"

    # asset hash
    buf = WriteVarBytes(args[0], None)
    # address
    buf = WriteVarBytes(args[1], buf)
    # token id TODO: 256?
    buf = WriteUint255(args[2], buf)
    # token URI
    buf = WriteVarBytes(args[3], buf)

    return buf


def _deserializeArgs(buf):
    offset = 0
    res = NextVarBytes(buf, offset)
    assetHash = res[0]

    res = NextVarBytes(buf, res[1])
    toAddress = res[0]

    res = NextUint255(buf, res[1])
    tokenId = res[0]

    res = NextVarBytes(buf, res[1])
    tokenURI = res[0]

    return [assetHash, toAddress, tokenId, tokenURI]

def WriteBool(v, buff):
    if v == True:
        buff = concat(buff, b'\x01')
    elif v == False:
        buff = concat(buff, b'\x00')
    else:
        assert (False)
    return buff


def WriteByte(v, buff):
    assert (len(v) == 1)
    vBs = v[0:1]
    buff = concat(buff, vBs)
    return buff


def WriteUint8(v, buff):
    assert (v >= 0 and v <= 0xFF)
    buff = concat(buff, _convertNumToBytes(v, 1))
    return buff


def WriteUint16(v, buff):
    assert (v >= 0 and v <= 0xFFFF)
    buff = concat(buff, _convertNumToBytes(v, 2))
    return buff


def WriteUint32(v, buff):
    assert (v >= 0 and v <= 0xFFFFFFFF)
    buff = concat(buff, _convertNumToBytes(v, 4))
    return buff


def WriteUint64(v, buff):
    assert (v >= 0 and v <= 0xFFFFFFFFFFFFFFFF)
    buff = concat(buff, _convertNumToBytes(v, 8))
    return buff


def WriteUint255(v, buff):
    assert (v >= 0 and v <= 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff)
    return WriteBytes(_convertNumToBytes(v, 32), buff)


def WriteVarUint(v, buff):
    if v < 0xFD:
        return WriteUint8(v, buff)
    elif v <= 0xFFFF:
        buff = concat(buff, 0xFD)
        return WriteUint16(v, buff)
    elif v <= 0xFFFFFFFF:
        buff = concat(buff, 0xFE)
        return WriteUint32(v, buff)
    else:
        buff = concat(buff, 0xFF)
        return WriteUint64(v, buff)


def WriteBytes(v, buff):
    return concat(buff, v)


def WriteVarBytes(v, buff):
    l = len(v)
    buff = WriteVarUint(l, buff)
    return WriteBytes(v, buff)


def WriteBytes20(v, buff):
    assert (len(v) == 20)
    return WriteBytes(v, buff)


def WriteBytes32(v, buff):
    assert (len(v) == 32)
    return WriteBytes(v, buff)


def WriteString(v, buff):
    return WriteVarBytes(v, buff)


def _convertNumToBytes(_val, bytesLen):
    l = len(_val)
    if l < bytesLen:
        for i in range(bytesLen - l):
            _val = concat(_val, b'\x00')
    if l > bytesLen:
        _val = _val[:bytesLen]
    return _val


def NextBool(buff, offset):
    if offset + 1 > len(buff):
        return [False, -1]
    val = buff[offset:offset + 1]
    if val == 1:
        return [True, offset + 1]
    elif val == 0:
        return [False, offset + 1]
    assert (False)


def NextByte(buff, offset):
    if offset + 1 > len(buff):
        return [0, -1]
    return [buff[offset:offset + 1], offset + 1]


def NextUint8(buff, offset):
    if offset + 1 > len(buff):
        return [0, -1]
    num = _convertBytesToNum(buff[offset:offset + 1])
    assert (num >= 0 and num <= 0xFF)
    return [num, offset + 1]


def NextUint16(buff, offset):
    if offset + 2 > len(buff):
        return [0, -1]
    num = _convertBytesToNum(buff[offset:offset + 2])
    assert (num >= 0 and num <= 0xFFFF)
    return [num, offset + 2]


def NextUint32(buff, offset):
    if offset + 4 > len(buff):
        return [0, -1]
    num = _convertBytesToNum(buff[offset:offset + 4])
    assert (num >= 0 and num <= 0xFFFFFFFF)
    return [num, offset + 4]


def NextUint64(buff, offset):
    if offset + 8 > len(buff):
        return [0, -1]
    num = _convertBytesToNum(buff[offset:offset + 8])
    assert (num >= 0 and num <= 0xFFFFFFFFFFFFFFFF)
    return [num, offset + 8]


def NextUint255(buff, offset):
    if offset + 32 > len(buff):
        return [0, -1]
    num = _convertBytesToNum(buff[offset:offset + 32])
    assert (num >= 0 and num <= 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff)
    return [num, offset + 32]


def NextBytes(buff, offset, count):
    if offset + count > len(buff):
        return [0, -1]
    return [buff[offset:offset + count], offset + count]


def NextVarUint(buff, offset):
    res = NextByte(buff, offset)
    fb = res[0]
    offset = res[1]
    assert (res[1] > 0)
    # we can also use if concat(fb, b'\x00') == 0xfd:
    if fb == b'\xfd':
        return NextUint16(buff, offset)
    elif fb == b'\xfe':
        return NextUint32(buff, offset)
    elif fb == b'\xff':
        return NextUint64(buff, offset)
    else:
        return [fb, offset]


def NextVarBytes(buff, offset):
    res = NextVarUint(buff, offset)
    return NextBytes(buff, res[1], res[0])


def NextBytes20(buff, offset):
    if offset + 20 > len(buff):
        return [0, -1]
    return [buff[offset:offset + 20], offset + 20]


def NextBytes32(buff, offset):
    if offset + 32 > len(buff):
        return [0, -1]
    return [buff[offset:offset + 32], offset + 32]


def NextString(buff, offset):
    return NextVarBytes(buff, offset)


def _convertBytesToNum(_bs):
    firstNonZeroPostFromR2L = _getFirstNonZeroPosFromR2L(_bs)
    assert (firstNonZeroPostFromR2L >= 0)
    # in case the last byte of _bs is greater than 0x80,
    # we need to append a byte of zero to mark it as positive
    if firstNonZeroPostFromR2L > len(_bs):
        _bs = concat(_bs, b'\x00')
        # here we add this condition to limit the converted bytes has the maximum length of 32.
        # The reason is ontology can recognize a 33 byte as a number which can be greater than the 32 bytes length number
        assert (len(_bs) <= 32)
        return _bs
    else:
        return _bs[:firstNonZeroPostFromR2L]


def _getFirstNonZeroPosFromR2L(_bs):
    bytesLen = len(_bs)
    for i in range(bytesLen):
        byteI = _bs[bytesLen - i - 1:bytesLen - i]
        if byteI != b'\x00':
            # convert byte to int
            byteI = concat(byteI, b'\x00')
            if byteI >= 0x80:
                return bytesLen + 1 - i
            else:
                return bytesLen - i
    return -1