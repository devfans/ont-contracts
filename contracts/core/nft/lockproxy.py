OntCversion = '2.0.0'
"""
Smart contract for locking and unlocking cross chain NFT asset between Ontology and other chains
"""

from ontology.interop.System.Action import RegisterAction
from ontology.interop.System.ExecutionEngine import GetExecutingScriptHash
from ontology.interop.System.Storage import Put, GetContext, Get
from ontology.interop.Ontology.Runtime import Base58ToAddress
from ontology.interop.System.Runtime import CheckWitness, Notify, Serialize, Deserialize
from ontology.builtins import concat, state, append, remove
from ontology.interop.System.App import DynamicAppCall



# Key prefix
OPERATOR_PREFIX = "Operator"
PROXY_HASH_PREFIX = "ProxyHash"


# Common
ctx = GetContext()
SelfContractAddress = GetExecutingScriptHash()

Operator = Base58ToAddress("xxx")
ZeroAddress = bytearray(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
CrossChainContractAddress = bytearray(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x09')


# Events 
UnlockEvent = RegisterAction("unlock", "toAssetHash", "toAddress", "amount")
LockEvent = RegisterAction("lock", "fromAssetHash", "fromAddress", "toAssetHash", "toAddress", "toChainId", "tokenId")

def Main(operation, args):
    return True


def init():
    """
    Set initial contract operator
    """
    assert (len(Get(ctx, OPERATOR_PREFIX)) == 0)
    Put(ctx, OPERATOR_PREFIX, operator)
    return True
    

def _serializeArgs(args):
    assert (len(args) == 4)
    
    # asset hash
    buf = WriteVarBytes(args[0], None)
    # address
    buf = WriteVarBytes(args[1], buf)
    # token id TODO: 256?
    buf = WriteUint255(args[2], buf)
    # token URI
    buf = WriteVarBytes(args[3], buf)
    
    return buf


def _deserialzieArgs(buf):
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

    
def bindProxyHash(chainId, targetProxyHash):
    """
    Bind chain id with proxy hash
    :param toChainId: chain id
    :param targetProxyHash: proxy hash
    :return: True
    """
    assert (CheckWitness(ctx, OPERATOR_PREFIX))
    Put(ctx, concat(PROXY_HASH_PREFIX, chainId), targetProxyHash)
    return True
    
def getProxyHash(chainId):
    """
    Get bound chain proxy hash from context
    :param toChainId: chain id
    :return: chain bound proxy hash
    """
    return Get(ctx, concat(PROXY_HASH_PREFIX, chainId))
    
def isAddress(address):
    """
    Validate address, check length, and not zero address
    :param address: address
    :return: True or raise exception
    """
    assert (len(address) == 20 and address != ZeroAddress)
    return True
    
def onERC721Received(operator, fromAddress, tokenId, params):
    """
    On erc721 asset received, trigger the cross chain contract call.
    :param operator: operator address
    :param fromAddress: from address
    :pram tokenId: token id
    :param params: argument list [assetHash, address, tokenId, tokenURI]
    :return: True or raise exception
    """
    assert (CheckWitness(fromAddress))
    
    txData = _serializeArgs([toAssetHash, toAddress, tokenId, tokenURI])
    args = state(toChainId, toProxyHash, "unlock", txData)
    assert (Invoke(0, CrossChainContractAddress, "createCrossChainTx", args))
    
    LockEvent()
    return True

def unlock(params, fromContractAddr, fromChainId):
    """
    Unlock nft asset from proxy lock to finish the cross chain transaction
    :param params: packed argument list [assetHash, address, tokenId, tokenURI]
    :param fromContractAddr: the invoker contract address
    :param: fromChainId: source chain id on poly network
    :returns:
    """
    assert (CheckWitness(CrossChainContractAddress))
    assert (getProxyHash(fromChainId) == fromContractAddr)
    
    assetHash, address, tokenId, tokenURI = _deserializeArgs(params)
    assert (isAddress(assetHash))
    assert (isAddress(address))
    
    owner = DynamicAppCall(assetHash, "ownerOf", tokenId)
    if owner != ZeroAddress:
        assert (owner == SelfContractAddress)
        res = DynamicAppCall(assetHash, "safeTransferFrom", [SelfContractAddress, address, tokenId])
    else:
        res = DynamicAppCall(assetHash, "mintWithURI", [address, tokenId, tokenURI])
    assert (res and res == b'\x01')
    
    UnlockEvent(assetHash, address, tokenId)
    return True
    
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

