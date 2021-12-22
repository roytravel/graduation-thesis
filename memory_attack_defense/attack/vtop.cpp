#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include "windows.h"

u_int VirtualtoPhysical(FILE * filePointer, __int64 virtualAddr, u_int dtb) 
{
    //u_int offset = 0x60000;
    u_int offset = 0;
    u_long addrBuffer = 0;
    u_int valueBuffer = 0;
    u_int pfnBuffer = 0;
    u_int pml4e = ((virtualAddr >> 39) & 0x1FF) * 8; //cut 9 bits
    u_int pdpte = ((virtualAddr >> 30) & 0x1FF) * 8; //cut 9 bits
    u_int pde = ((virtualAddr >> 21) & 0x1FF) * 8; //cut 9 bits
    u_int pte = ((virtualAddr >> 12) & 0x1FF) * 8; //cut 9 bits(this is for PTE, 4KB Page size)
    u_int addrOffset4KB = virtualAddr & 0xFFF; //cut 12 bits(this is for PTE, 4KB Page size)
    u_int addrOffset2MB = virtualAddr & 0x1FFFFF; //cut 21 bits(this is for PTE, 2MB Page size)

    printf("pml4e Address : 0x%X\n", pml4e);
    printf("pdpte Address : 0x%X\n", pdpte);
    printf("pde Address : 0x%X\n", pde);
    printf("pte Address : 0x%X\n", pte);
    printf("addrOffset pageSize 4KB Address : 0x%X\n\n", addrOffset4KB);
    printf("addrOffset pageSize 2MB Address : 0x%X\n\n", addrOffset2MB);

    //This is pml4e calculating
    addrBuffer = (dtb + pml4e) - offset; 
    printf("1. PML4E Address : 0x%X\n", addrBuffer);
    _fseeki64(filePointer, addrBuffer, SEEK_SET);
    fread(&valueBuffer, 1, 4, filePointer);
    printf("1. valueBuffer : 0x%X\n", valueBuffer);
    valueBuffer &= 0xFFFFF000;
    printf("1. pml4e: 0x%X\n\n", valueBuffer);

    //This is pdpte calculating
    addrBuffer = (valueBuffer + pdpte) - offset;
    printf("2. PDPTE Address : 0x%X\n", addrBuffer);
    _fseeki64(filePointer, addrBuffer, SEEK_SET);
    fread(&valueBuffer, 1, 4, filePointer);
    printf("2. valueBuffer : 0x%X\n", valueBuffer);
    valueBuffer &= 0xFFFFF000;
    printf("2. PDPTE: 0x%X\n\n", valueBuffer);

    //This is pde calculating
    addrBuffer = (valueBuffer + pde) - offset;
    printf("3. PDE Address : 0x%X\n", addrBuffer);
    _fseeki64(filePointer, addrBuffer, SEEK_SET);
    fread(&valueBuffer, 1, 4, filePointer);
    printf("3. valueBuffer : 0x%X\n", valueBuffer);
    pfnBuffer = valueBuffer & 0xFFF;
    valueBuffer &= 0xFFFFF000;
    printf("3. The PFN Value of the PDE : 0x%X\n", pfnBuffer);
    printf("3. PDE: 0x%X\n\n", valueBuffer);

    if ((pfnBuffer& (1 << 7)) == (1 << 7)) 
    {
        printf("\n----2MB paging!!!----\n");
        //This is for adding addrOffset
        valueBuffer += addrOffset2MB;
        return (valueBuffer - offset);
    }
    
    else 
    {
    printf("\n----4KB paging!!!----\n");
    //This is pte calculating
    addrBuffer = (valueBuffer + pte) - offset;
    printf("4. PTE Address : 0x%X\n", addrBuffer);
    _fseeki64(filePointer, addrBuffer, SEEK_SET);
    fread(&valueBuffer, 1, 4, filePointer);
    printf("4. valueBuffer : 0x%X\n", valueBuffer);
    valueBuffer &= 0xFFFFF000;
    printf("4. PTE: 0x%X\n\n", valueBuffer);
    //This is for adding addrOffset
    valueBuffer += addrOffset4KB;
    return (valueBuffer - offset);
    }
}


int main()
{
    char * buffer = "C:\\FileName";
    //Input VirtualAddress And DTB Value
    __int64 virtualAddrBuf = 0xFFFFFA801A7D1A38;
    u_int dtbBuf = 0x57dea000;
    FILE * filePointer = NULL;

    filePointer = fopen(buffer, "rb");
    if (filePointer == NULL) 
    {
        printf("File Open Failed!\n");
        return 0;
    }

    VirtualtoPhysical(filePointer, virtualAddrBuf, dtbBuf);
    fclose(filePointer);

    return 0;
}