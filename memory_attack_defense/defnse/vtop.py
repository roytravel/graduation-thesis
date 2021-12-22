# -*- coding:utf-8 -*-
import struct
import sys
# diffOffset = 0x60000
diffOffset = 0
def write(offset,value,trans,result):
    print ("\nOffset(P) : {}\n\t[VALUE ] : 0x{}\n\t[TRANS ] :{}\n\t[RESULT] : {}\n".format(hex(offset), value.encode('hex'), hex(trans), hex(result)))
    
    
def is48bit(vaddr):
    initalBit = bin(int(vaddr,16)).replace('0b','')
    if len(initalBit) != 48:
        lackCount = 48 - len(initalBit)
        zeroFill = '0' * lackCount
        complete = zeroFill + initalBit
        return complete
    else:
        return initalBit
    

def checkPFN(trans3):
    pfn = bin(trans3).replace('0b', '')[-12:]
    if pfn[4]=="1":
        return True
    elif pfn[4]=="0":
        return False
    
    
def vtop(memory, vaddr, dtb):
    bit = is48bit(vaddr)
    pml4et = hex(int(bit[0:9],2)*8)
    pdpt = hex(int(bit[9:18],2)*8)
    pdt = hex(int(bit[18:27],2)*8)
    p = hex(int(bit[27:48],2))
    ptt4K = hex(int(bit[27:36],2)*8)
    p4K = hex(int(bit[36:48],2))
    print ("[비트계산]\n\t[09bit]{}\n\t[09bit] {}\n\t[09bit] {}\n\t[21bit] {}".format(pml4et,pdpt,pdt,p))
    
    
    firstAddr = int(dtb) + int(pml4et,16)
    firstAddr = firstAddr - diffOffset
    memory.seek(firstAddr)
    pml4e = memory.read(4)
    trans1 = struct.unpack("<L",pml4e)[0]
    
    result1 = trans1 - (0xfff & trans1)
    write(firstAddr, pml4e, trans1, result1)
    secondAddr = int(hex(result1), 16) + int(pdpt, 16)
    secondAddr = secondAddr - diffOffset
    memory.seek(secondAddr)
    pdpe = memory.read(4)
    trans2 = struct.unpack("<L", pdpe)[0]
    result2 = trans2 - (0xfff & trans2)
    write(secondAddr, pdpe, trans2, result2)
    thirdAddr = int(hex(result2),16) + int(pdt,16)
    thirdAddr = thirdAddr - diffOffset
    memory.seek(thirdAddr)
    pde = memory.read(4)
    trans3 = struct.unpack("<L",pde)[0]
    result3 = trans3 - (0xfff & trans3)
    write(thirdAddr,pde,trans3,result3)


    flag = checkPFN(trans3)
    if flag==True:
        lastResult = int(hex(result3),16) + int(p,16)
        print ("[FINAL]: 당신이 찾는 물리주소는["+hex(lastResult)+"]입니다.")
        
    elif flag==False:
        fourthAddr = int(hex(result3), 16) + int(ptt4K, 16)
        memory.seek(fourthAddr)
        ptt = memory.read(4)
        trans4 = struct.unpack("<L", ptt)[0]
        result4 = trans4 - (0xfff & trans4)
        write(fourthAddr, ptt, trans4, result4)
        lastResult = int(hex(result4), 16) + int(p4K, 16)
        print ("[FINAL]: 당신이 찾는 물리주소는[" + hex(lastResult) + u"]입니다.")
        
    
if __name__=='__main__':
    if len(sys.argv) !=4:
        print ("사용법 : [FILE] [VIRTUAL] [DTB]")
    else:
        with open(sys.argv[1],'rb') as dump:
            vtop(dump,sys.argv[2],sys.argv[3])
