OntCversion = '2.0.0'
"""
Smart contract for wrapping cross chain NFT asset locking between Ontology and other chains provided by poly
"""

from ontology.interop.Ontology.Native import Invoke
from ontology.interop.System.Action import RegisterAction
from ontology.interop.System.Storage import Put, GetContext, Get, Delete
from ontology.interop.System.Runtime import CheckWitness
from ontology.libont import bytearray_reverse
from ontology.interop.System.App import DynamicAppCall
from ontology.builtins import concat, state


# Key prefix
OWNER_KEY = "owner"
FEE_COLLECTOR_KEY = "feeCollector"
LOCK_PROXY_KEY = "lockProxy"
PAUSE_KEY = "pause"

# Constant
OntChainIdOnPoly = 3
ZeroAddress = bytearray(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
ONGAddress = bytearray(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02')

# Event
TransferOwnership = RegisterAction("TransferOwnership", "oldOwner", "newOwner")
PolyWrapperLock = RegisterAction("PolyWrapperLock", "fromAsset", "msgSender", "toChainId", "toAddress", "tokenId", "feeToken", "fee", "id");
PolyWrapperSpeedUp = RegisterAction("PloyWrapperSpeedUp", "feeToken", "txHash", "sender", "efee")

def Main(operation, args):
    if operation == "init":
        assert (len(args) == 3)
        owner = args[0]
        feeCollector = args[1]
        lockProxy = args[2]
        return init(owner, feeCollector, lockProxy)
    if operation == "setFeeCollector":
        assert (len(args) == 1)
        return setFeeCollector(args[0])
    if operation == "getFeeCollector":
        return getFeeCollector()
    if operation == "setLockProxy":
        assert (len(args) == 1)
        lockProxy = args[0]
        return setLockProxy(lockProxy)
    if operation == "getLockProxy":
        return getLockProxy()
    if operation == "pause":
        return pause()
    if operation == "unpause":
        return unpause()
    if operation == "ifPause":
        return ifPause()
    if operation == "lock":
        assert len(args) == 8, "Invalid args length for lock"
        return lock(args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7])
    if operation == "speedUp":
        assert len(args) == 4, "Invalid args length for speedUp"
        return speedUp(args[0], args[1], args[2], args[3])
    if operation == "transferOwnership":
        assert (len(args) == 1)
        newOwner = args[0]
        return transferOwnership(newOwner)
    if operation == "setLockProxy":
        assert (len(args) == 1)
        return setLockProxy(args[0])

    return False


def init(owner, feeCollector, lockProxy):
    """
    owner: address type
    feeCollector: address receiving fee
    lockProxy: lockProxy hash
    """
    assert (CheckWitness(owner))
    Put(GetContext(), OWNER_KEY, owner)
    Put(GetContext(), FEE_COLLECTOR_KEY, feeCollector)
    Put(GetContext(), LOCK_PROXY_KEY, bytearray_reverse(lockProxy))
    TransferOwnership("", owner)
    return True


def setFeeCollector(feeCollector):
    """
    :param feeCollector: address
    :return:
    """
    assert (CheckWitness(getOwner()))
    Put(GetContext(), FEE_COLLECTOR_KEY, feeCollector)
    return True


def getFeeCollector():
    return Get(GetContext(), FEE_COLLECTOR_KEY)


def setLockProxy(lockProxy):
    """
    :param lockProxy: ont lock proxy
    :return:
    """
    assert (CheckWitness(getOwner()))
    Put(GetContext(), LOCK_PROXY_KEY, bytearray_reverse(lockProxy))
    return True


def getLockProxy():
    return Get(GetContext(), LOCK_PROXY_KEY)


def pause():
    assert (CheckWitness(getOwner()))
    Put(GetContext(), PAUSE_KEY, True)
    return True


def unpause():
    assert (CheckWitness(getOwner()))
    Delete(GetContext(), PAUSE_KEY)
    return True


def ifPause():
    return Get(GetContext(), PAUSE_KEY)

def lock(fromAddress, fromAsset, toChainId, toAddress, tokenId, feeToken, fee, id):
    """
    :param fromAddress: source token address
    :param fromAsset: source asset hash
    :param toChainId: target chain id
    :param toAddress: target address
    :param tokenId: nft asset token id
    :param feeToken: fee asset hash
    :param fee: fee amount
    :param id:
    :return: True or raise exception
    """
    assert CheckWitness(fromAddress), "Invalid from address witness"
    assert (not ifPause()), "Contract paused"
    assert isValidAddress(toAddress)
    assert (feeToken == ONGAddress), "Fee token should be ONG"
    assert (toChainId != OntChainIdOnPoly), "Target chain can not be ONT"
    assert (fee > 0), "Fee should not be zero"

    lockProxy = getLockProxy()
    toAssethash = DynamicAppCall(lockProxy, 'getAssetHash', [fromAsset, toChainId])
    assert (len(toAssethash) == 20), "No toAssetHash bound"

    # transfer fee to fee collector
    feeCollector = getFeeCollector()
    assert isValidAddress(feeCollector)

    owner = DynamicAppCall(fromAsset, "ownerOf", [tokenId])
    assert (isValidAddress(owner) and owner == fromAddress), "Invalid owner address"

    # approve and transfer fee
    res = DynamicAppCall(fromAsset, "approve", [lockProxy, tokenId])
    assert (res and res == b'\x01'), "nft token approve failed"
    param = state(fromAddress, feeCollector, fee)
    res = Invoke(0, feeToken, 'transfer', [param])
    assert (res and res == b'\x01'), "Fee transfer failed"

    params = _serializeCallData([toAddress, toChainId])
    res = DynamicAppCall(lockProxy, 'lock', [fromAddress, tokenId, params])
    assert (res and res == b'\x01'), "lockProxy failed"

    PolyWrapperLock(fromAsset, fromAddress, toChainId, toAddress, tokenId, feeToken, fee, id)
    return True

def speedUp(fromAddress, feeToken, txHash, fee):
    """
    Speed up cross chain transaction
    :param fromAddress: fee from address
    :param feeToken: fee token
    :param txHash: cross chain transaction hash
    :param fee: fee amount
    :return: True or raise exception
    """
    assert CheckWitness(fromAddress), "Invalid witness"
    assert (feeToken == ONGAddress), "Fee token should be ONG"

    # transfer fee to fee collector
    feeCollector = getFeeCollector()
    assert isValidAddress(feeCollector)

    param = state(fromAddress, feeCollector, fee)
    res = Invoke(0, feeToken, 'transfer', [param])
    assert (res and res == b'\x01'), "Fee transfer failed"
    PolyWrapperSpeedUp(feeToken, txHash, fromAddress, fee)
    return True

def transferOwnership(newOwner):
    oldOwner = getOwner()
    assert (CheckWitness(oldOwner))
    Put(GetContext(), OWNER_KEY, newOwner)
    TransferOwnership(oldOwner, newOwner)
    return True


def getOwner():
    return Get(GetContext(), OWNER_KEY)

def isValidAddress(address):
    """
    Validate address, check length, and not zero address
    :param address: address
    :return: True or raise exception
    """
    assert (len(address) == 20 and address != Z), "Invalid address"
    return True


def _serializeCallData(args):
    assert len(args) == 2, "Invalid args length"
    # address
    buf = WriteVarBytes(args[0], None)
    # chain Id
    buf = WriteUint64(args[2], buf)

    return buf


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