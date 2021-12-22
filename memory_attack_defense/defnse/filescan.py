# -*- coding:utf-8 -*-

import struct
import sys
import time

# >>> dt("_FILE_OBJECT")
#  '_FILE_OBJECT' (216 bytes)
# 0x0   : Type                           ['short']
# 0x2   : Size                           ['short']
# 0x8   : DeviceObject                   ['pointer64', ['_DEVICE_OBJECT']]
# 0x10  : Vpb                            ['pointer64', ['_VPB']]
# 0x18  : FsContext                      ['pointer64', ['void']]
# 0x20  : FsContext2                     ['pointer64', ['void']]
# 0x28  : SectionObjectPointer           ['pointer64', ['_SECTION_OBJECT_POINTERS']]
# 0x30  : PrivateCacheMap                ['pointer64', ['void']]
# 0x38  : FinalStatus                    ['long']
# 0x40  : RelatedFileObject              ['pointer64', ['_FILE_OBJECT']]
# 0x48  : LockOperation                  ['unsigned char']
# 0x49  : DeletePending                  ['unsigned char']
# 0x4a  : ReadAccess                     ['unsigned char']
# 0x4b  : WriteAccess                    ['unsigned char']
# 0x4c  : DeleteAccess                   ['unsigned char']
# 0x4d  : SharedRead                     ['unsigned char']
# 0x4e  : SharedWrite                    ['unsigned char']
# 0x4f  : SharedDelete                   ['unsigned char']
# 0x50  : Flags                          ['unsigned long']
# 0x58  : FileName                       ['_UNICODE_STRING']
# 0x68  : CurrentByteOffset              ['_LARGE_INTEGER']
# 0x70  : Waiters                        ['unsigned long']
# 0x74  : Busy                           ['unsigned long']
# 0x78  : LastLock                       ['pointer64', ['void']]
# 0x80  : Lock                           ['_KEVENT']
# 0x98  : Event                          ['_KEVENT']
# 0xb0  : CompletionContext              ['pointer64', ['_IO_COMPLETION_CONTEXT']]
# 0xb8  : IrpListLock                    ['unsigned long long']
# 0xc0  : IrpList                        ['_LIST_ENTRY']
# 0xd0  : FileObjectExtension            ['pointer64', ['void']]

dtb = 0x187000
diffOffset=0
signatureA = "0500d80000000000"
signatureB = "0004000080010000"
signatureC = "001502"
signatureD = "1c000c"
filescanPoolTag = "46696ce5"
hidden = list()
seq = list()


def initalHello():
    print u"\n[+] 파일 목록 탐색을 시작합니다"
    time.sleep(2)
    print u"  [-] 파일 크기에 따라 탐색 시간이 길어질 수 있습니다...\n"
    time.sleep(2)
    print "%-24s" % "Offset(P)", "%-30s" % "Offset(F)", "PATH"

def result(hidden,index):
    print u"\n---------------탐색 결과 보고---------------------"
    print u"[+] 은폐 파일 오브젝트는 {}개 입니다.".format(len(hidden))
    for j in range(0,len(hidden),1):
        print "  [-] Offset(P) : {} | PATH : {}".format(hex(index[j]),hidden[j])
    print "--------------------------------------------------"

def checkPFN(trans3):
    pfn = bin(trans3).replace('0b', '')[-12:]
    if pfn[4]=="1":
        return True
    elif pfn[4]=="0":
        return False

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
        return hex(lastResult)

    elif flag == False:
        fourthAddr = int(hex(result3), 16) + int(ptt4K, 16)
        dump.seek(fourthAddr)
        ptt = dump.read(4)
        trans4 = struct.unpack("<L", ptt)[0]
        result4 = trans4 - (0xfff & trans4)
        # write(fourthAddr, ptt, trans4, result4)
        lastResult = int(hex(result4), 16) + int(p4K, 16)
        return hex(lastResult)

def main(dump):
    memory = dump.read()
    initalHello()
    for index in range(len(memory)/2+len(memory)/4+len(memory)/8,len(memory)+8,8):
        character = memory[index:index+8].encode('hex')
        if character == signatureA and signatureD==memory[index-0x18:index-0x15].encode('hex') and signatureB==memory[index-0x60:index-0x58].encode('hex'):
            fileNamePointer = memory[index+0x60:index+0x68]
            fileNamePointer2 = struct.unpack("<Q",fileNamePointer)[0]
            fileNamePointer3 = (fileNamePointer2 & 0x0000ffffffffffff)
            fileNamePointer4 = hex(fileNamePointer3)[0:14].strip("L")
            if int(fileNamePointer4,16)!=0:
                pFileName = vtop(memory,fileNamePointer4,dtb)
                pFileName = int(pFileName,16)
                dump.seek(pFileName)
                path = dump.read(100).replace('\x00','')
                tmp = str(path).decode('utf-8','replace').replace('\n','')
                partPathdll = list(tmp.partition('.dll'))
                # partPathexe = list(tmp.partition('.exe'))
                if partPathdll[1][-4:]==".dll":
                    print ("{}\t\t {}\t\t {}".format(hex(index),hex(pFileName),partPathdll[0]+partPathdll[1]))

                if (memory[index-0x6c:index-0x68].encode('hex') !=filescanPoolTag) or memory[index-0x6f:index-0x6c].encode('hex') !=signatureC:
                        hidden.append(partPathdll[0]+partPathdll[1])
                        seq.append(index)
    result(hidden,seq)
    print u"Offset(P) : [{}] 영역의 풀태그는 변조되었습니다.".format(hex(index))

if __name__=='__main__':
    if len(sys.argv) != 2:
        print "usage : filescan.py [FILE]"
    else:
        with open(sys.argv[1],'rb') as dump:
            main(dump)
