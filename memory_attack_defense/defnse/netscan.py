# -*- coding:utf-8 -*-

import sys
import struct
import socket
import time
# >>> dt("_TCP_ENDPOINT")
#  '_TCP_ENDPOINT' (None bytes)
# 0x0   : CreateTime                     ['WinTimeStamp', {'is_utc': True, 'value': 0}]
# 0x18  : InetAF                         ['pointer', ['_INETAF']]
# 0x20  : AddrInfo                       ['pointer', ['_ADDRINFO']]
# 0x28  : ListEntry                      ['_LIST_ENTRY']
# 0x68  : State                          ['Enumeration', {'target': 'long', 'choices': {0: 'CLOSED', 1: 'LISTENING', 2: 'SYN_SENT', 3: 'SYN_RCVD', 4: 'ESTABLISHED', 5: 'FIN_WAIT1', 6: 'FIN_WAIT2', 7: 'CLOSE_WAIT', 8: 'CLOSING', 9: 'LAST_ACK', 12: 'TIME_WAIT', 13: 'DELETE_TCB'}}]
# 0x6c  : LocalPort                      ['unsigned be short']
# 0x6e  : RemotePort                     ['unsigned be short']
# 0x238 : Owner                          ['pointer', ['_EPROCESS']]

# >>> dt("_ADDRINFO")
#  '_ADDRINFO' (None bytes)
# 0x0   : Local                          ['pointer', ['_LOCAL_ADDRESS']]
# 0x10  : Remote                         ['pointer', ['_IN_ADDR']]

# >>> dt("_LOCAL_ADDRESS")
#  '_LOCAL_ADDRESS' (None bytes)
# 0x10  : pData                          ['pointer', ['pointer', ['_IN_ADDR']]]

# >>> dt("_IN_ADDR")
#  '_IN_ADDR' (None bytes)
# 0x0   : addr4                          ['IpAddress']
# 0x0   : addr6                          ['Ipv6Address']

signature = "00000000000000000200000000000000"
distinctCode = "ffff"
stateCode = "04000000"
stateCod3 = "00000000"
dtb = 0x187000
diffOffset = 0 #0x60000 : if 2GB dmp
hiddenO=list()
hiddenP=list()

def initalHello():
    print "\n",
    print u"[+] 네트워크 연결정보 탐색을 시작합니다"
    time.sleep(2)
    print u"  [-] 파일 크기에 따라 탐색 시간이 길어질 수 있습니다...\n"
    time.sleep(2)
    print "%-17s" %("Offset(P)"),"%-16s" %("Process"), "%-14s" %("State"), "%-15s" %("EPROCESS"), "%-23s" %("Local Address"), ("Remote Address")

def write(offset,value,trans,result):
    print u"\nOffset(P) : {}\n\t[VALUE ] : 0x{}\n\t[TRANS ] : {}\n\t[RESULT] : {}\n".format(hex(offset), value.encode('hex'), hex(trans), hex(result))

def checkPFN(trans3):
    pfn = bin(trans3).replace('0b', '')[-12:]
    if pfn[4]=="1":
        return True
    elif pfn[4]=="0":
        return False

def checkSTATE(state):
    if state=="0000000000":
        return "CLOSED"
    elif state=="01000000":
        return "LISTENING"
    elif state=="04000000":
        return "ESTABLISHED"
    elif state=="08000000":
        return "CLOSING"

def is48bit(test):
    test = test.strip("L")
    initalBit = bin(int(test,16)).replace('0b','')
    if len(initalBit) != 48:
        lackCount = 48 - len(initalBit)
        zeroFill = '0' * lackCount
        complete = zeroFill + initalBit
        return complete
    else:
        return initalBit

def calc(nAddr):
    nAddr = nAddr - diffOffset
    dump.seek(nAddr)
    pml4e = dump.read(4)
    trans = struct.unpack("<L", pml4e)[0]
    result = trans - (0xfff & trans)
    return result

def vtop(memory, vaddr, dtb):
    bit = bin(int(vaddr.strip("L"), 16))
    bit = is48bit(vaddr)
    # bit = bit[2:50]
    pml4et = hex(int(bit[0:9],2)*8)
    pdpt = hex(int(bit[9:18], 2)*8)
    pdt = hex(int(bit[18:27],2)*8)
    p = hex(int(bit[27:48], 2))
    ptt4K = hex(int(bit[27:36],2)*8)
    p4K = hex(int(bit[36:48],2))

    firstAddr = int(dtb) + int(pml4et, 16)
    result1 = calc(firstAddr)

    secondAddr = int(hex(result1), 16) + int(pdpt, 16)
    result2 = calc(secondAddr)
    result2 = hex(result2).strip("L")

    thirdAddr = int(result2, 16) + int(pdt, 16)
    thirdAddr = thirdAddr - diffOffset
    dump.seek(thirdAddr)
    pde = dump.read(4)
    trans3 = struct.unpack("<L",pde)[0]
    result3 = trans3 - (0xfff & trans3)

    flag = checkPFN(trans3)

    if flag == True:
        lastResult = int(hex(result3), 16) + int(p, 16)
        # print u"[FINAL]:  당신이 찾는 물리주소는[" + hex(lastResult) + u"]입니다."
        return hex(lastResult)

    elif flag == False:
        fourthAddr = int(hex(result3), 16) + int(ptt4K, 16)
        dump.seek(fourthAddr)
        ptt = dump.read(4)
        trans4 = struct.unpack("<L", ptt)[0]
        result4 = trans4 - (0xfff & trans4)
        # write(fourthAddr, ptt, trans4, result4)
        lastResult = int(hex(result4), 16) + int(p4K, 16)
        # print u"[FINAL]:  당신이 찾는 물리주소는[" + hex(lastResult) + u"]입니다."
        return hex(lastResult)

def transEprocess(EPROCESS):
    realEprocess = struct.unpack("<Q", EPROCESS)[0]
    compactEprocess = (realEprocess & 0x0000ffffffffffff)
    substantialEprocess = hex(compactEprocess)[0:14]
    return substantialEprocess

def getEprocessName(pEprocess):
    intpEprocess = int(pEprocess, 16)
    dump.seek(intpEprocess + 0x2e0)
    psName = dump.read(16).replace('\x00', '').replace('\x01', '').replace('\x02', '')
    return psName

def getAddrInfoStructure(memory,index):
    addrInfo = memory[index + 0x20:index + 0x28]
    realAddrinfo = struct.unpack("<Q", addrInfo)[0]
    compactAddrinfo = (realAddrinfo & 0x0000ffffffffffff)
    substantialAddrinfo = hex(compactAddrinfo)[0:14]
    return substantialAddrinfo

def findVirtualLocalAddr(pAddrInfoField):
    intpAddrInfo = int(pAddrInfoField, 16)
    dump.seek(intpAddrInfo)  # LocalAddress Pointer
    vLocalAddr = dump.read(8)
    realLocalAddr = struct.unpack("<Q", vLocalAddr)[0]
    compactLocalAddr = (realLocalAddr & 0x0000ffffffffffff)
    substantialLocalAddr = hex(compactLocalAddr)[0:14].strip("L")
    return substantialLocalAddr,intpAddrInfo

def getLocalAddrPointer(pLocalAddr):
    intLocalAddr = int(pLocalAddr, 16)
    intLocalAddr = intLocalAddr + 0x10
    dump.seek(intLocalAddr)
    vLocalPointer = dump.read(8)
    realLocalPointer = struct.unpack("<Q", vLocalPointer)[0]
    compactLocalPointer = (realLocalPointer & 0x0000ffffffffffff)
    substantialLocalPointer = hex(compactLocalPointer)[0:14]
    return substantialLocalPointer

def getRealLocalAddrPointer(physicalLocalAddr):
    intPhysicalLocalAddr = int(physicalLocalAddr, 16)
    dump.seek(intPhysicalLocalAddr)
    vPhysicalLocalAddr = dump.read(8)
    realLocalAddrPointer = struct.unpack("<Q", vPhysicalLocalAddr)[0]
    compactLocalAddrPointer = (realLocalAddrPointer & 0x0000ffffffffffff)
    substantialLocalAddrPointer = hex(compactLocalAddrPointer)[0:14]
    return substantialLocalAddrPointer

def getRealLocalIP(localAddr):
    intLocalAddr = int(localAddr, 16)
    dump.seek(intLocalAddr)
    reverseLocalAddr = dump.read(4).encode('hex')
    intLocalIP = int(reverseLocalAddr, 16)
    reverseLocalIP = struct.pack("<L", intLocalIP).encode('hex')
    realLocalIP = int(reverseLocalIP, 16)
    localIP = socket.inet_ntoa(struct.pack("<L", realLocalIP))
    return localIP

def getRealPhysicalAddr(intpAddrInfo):
    remoteAddrField = intpAddrInfo + 0x10
    dump.seek(remoteAddrField)
    vRemoteAddr = dump.read(8)
    realRemoteAddr = struct.unpack("<Q", vRemoteAddr)[0]
    compactRemoteAddr = (realRemoteAddr & 0x0000ffffffffffff)
    substantialRemoteAddr = hex(compactRemoteAddr)[0:14]
    return substantialRemoteAddr

def getRealRemoteIP(pRemoteAddr):
    intpRemoteAddr = int(pRemoteAddr, 16)
    dump.seek(intpRemoteAddr)
    remoteIP = dump.read(4).encode('hex')
    intRemoteIP = int(remoteIP, 16)
    reverseRemoteIP = struct.pack("<L", intRemoteIP).encode('hex')
    intReverseRemoteIP = int(reverseRemoteIP, 16)
    realRemoteIP = socket.inet_ntoa(struct.pack("<L", intReverseRemoteIP))
    return realRemoteIP

def result(hiddenO,hiddenP):
    print u"\n---------------탐색 결과 보고---------------------"
    print u"[+] 은폐 연결정보 {}개 입니다. (Owner : Offset)".format(len(hiddenO))
    for j in range(0,len(hiddenO),1):
        print u"  [-] {} | 은폐된 위치는 {} 입니다.".format(hiddenP[j],hiddenO[j])
    print u"--------------------------------------------------"


def checkPooltagManipulation(memory,index,psName):
    if memory[index - 0x0c:index - 0x08] != "TcpE":
        # print u"\t└은폐된 네트워크 연결정보 필드입니다."
        hiddenO.append(hex(index))
        hiddenP.append(psName)
        return hiddenO,hiddenP

def main(dump):
    memory = dump.read()
    initalHello()
    for index in range(len(memory)/2+len(memory)/4+len(memory)/8, len(memory), 16):
        firstFilter = memory[index:index+0x10].encode('hex')
        if (firstFilter == signature) and \
                (stateCode ==memory[index+104:index+108].encode('hex')):
            secondFilter = memory[index+0x16:index+0x18].encode('hex')
            if secondFilter == distinctCode:
                EPROCESS = memory[index + 0x238:index + 0x240]
                if EPROCESS.encode('hex')[12:16] == "ffff":
                    try:
                        substantialEprocess = transEprocess(EPROCESS)
                        pEprocess = vtop(dump,substantialEprocess,dtb)
                        psName = getEprocessName(pEprocess)
                        substantialAddrinfo = getAddrInfoStructure(memory,index)
                        pAddrInfoField = vtop(dump, substantialAddrinfo, dtb)
                        substantialLocalAddr, intpAddrInfo =\
                            findVirtualLocalAddr(pAddrInfoField)
                        pLocalAddr = vtop(dump,substantialLocalAddr,dtb)
                        substantialLocalPointer = getLocalAddrPointer(pLocalAddr)
                        physicalLocalAddr = vtop(dump,substantialLocalPointer,dtb)
                        substantialLocalAddrPointer =\
                            getRealLocalAddrPointer(physicalLocalAddr)
                        localAddr = vtop(dump,substantialLocalAddrPointer,dtb)
                        localIP = getRealLocalIP(localAddr)
                        localPort = memory[index+0x6c:index+0x6e].encode('hex')
                        substantialRemoteAddr = getRealPhysicalAddr(intpAddrInfo)
                        pRemoteAddr = vtop(dump,substantialRemoteAddr,dtb)
                        realRemoteIP = getRealRemoteIP(pRemoteAddr)
                        remotePort = memory[index+0x6e:index+0x70].encode('hex')
                        state = checkSTATE(memory[index+0x68:index+0x6c].encode('hex'))
                        print "{}\t{}\t{}\t {}\t{}:{}\t {}:{}".\
                            format(hex(index),psName,state,pEprocess,localIP,
                                   int(localPort,16),realRemoteIP,int(remotePort,16))
                        hiddenO,hiddenP = checkPooltagManipulation(memory,index,psName)
                    except Exception as e:
                        # print e
                        pass
    result(hiddenO,hiddenP)

if __name__=='__main__':
    if len(sys.argv) != 2:
        print "usage : netscan.py [FILE]"
    else:
        with open(sys.argv[1],'rb') as dump:
            main(dump)
