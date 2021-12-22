# -*- coding:utf-8 -*-

import sys
import struct
import time

signatureA = "0300580000000000"
signatureB = "0300580001000000"
signatureC = "00000000" # [i+0x2C:i+0x30] == Directroy Table Base Field so must be 00 00 00 00
hiddenCount = 0
processCount = 0
hiddenProcessName = list()

def initalSayHello():
    print "\n",
    print u"[+] 프로세스 탐색을 시작합니다"
    time.sleep(2)
    print u"  [-] 파일 크기에 따라 탐색 시간이 길어질 수 있습니다...\n"

def checkEprocess(dumpFile, index):
    dispatcherHeader = dumpFile[index:index+8]
    if (dispatcherHeader.encode('hex') == signatureA) or (dispatcherHeader.encode('hex') == signatureB):
        distinctCode = dumpFile[index+14 : index+16].encode('hex')
        flag = (False,True)[distinctCode=="ffff"]
        return flag

def findDTB(memory, index):
    memory.seek(index+0x28)
    fakeDTB = memory.read(4)
    trueDTB = struct.unpack("<L",fakeDTB)[0]
    return trueDTB

def findPID(memory, index):
    memory.seek(index+0x180)
    fakePID = memory.read(4)
    truePID = struct.unpack("<L",fakePID)[0]
    return truePID

def findPPID(memory, index):
    memory.seek(index+0x290)
    fakePPID = memory.read(4)
    truePPID = struct.unpack("<L",fakePPID)[0]
    return truePPID

def findProcessName(memory, index):
    memory.seek(index+0x2e0)
    processName = memory.read(16).replace('\x00','').replace('\x01','').replace('\x02','').replace('\x03','')
    return processName

def poolTag(memory, index):
    memory.seek(index-0x3c)
    poolTag1 = memory.read(4).encode('hex')
    memory.seek(index-0x5c)
    poolTag2 = memory.read(4).encode('hex')
    return (poolTag1,poolTag2)

def checkHiddenProcess(poolTag1,poolTag2,processName):
    hiddenProcess = list()
    if (poolTag1 != "50726fe3") and (poolTag2 != "50726fe3"):
        hiddenProcess.append(processName)
        return hiddenProcess

def result(processCount,count,hiddenProcessName):
    locateNumber = list()
    for j in range(len(hiddenProcessName)):
        if hiddenProcessName[j] != None :
            count = count + 1
            locateNumber.append(j)
    print u"\n---------------탐색 결과 보고---------------------"
    print u"[+] 정상 프로세스 {}개, 은폐 프로세스 {}개 입니다. ".format(processCount - count, count)
    for number in locateNumber:
        print u"  [-] 은폐된 프로세스는 {} 입니다.".format(hiddenProcessName[number])
    print u"--------------------------------------------------"

def main(memoryDump,processCount,count):
    initalSayHello()
    for index in range(len(memoryDump)/2+len(memoryDump)/4+len(memoryDump)/8,len(memoryDump),8):
        if checkEprocess(memoryDump,index):
            processCount = processCount + 1
            processID = findPID(memory,index)
            pprocessID = findPPID(memory,index)
            directoryTableBase = findDTB(memory,index)
            processName = findProcessName(memory,index)
            poolTagA, poolTagB = poolTag(memory,index)
            hiddenProcessName.append(checkHiddenProcess(poolTagA,poolTagB,processName))
            print "OFFSET(P) : {} DTB : {} PID : {} PPID : {} NAME : {}"\
                .format(hex(index), hex(directoryTableBase), processID, pprocessID, processName)
    result(processCount, count,hiddenProcessName)

if __name__=='__main__':
    if len(sys.argv) != 2:
        print "Usage : psscan.py [file]"
    else:
        with open(sys.argv[1],'rb') as memory:
            main(memory.read(),processCount,hiddenCount)