#include <stdio.h>
#include <inttypes.h>
#include <string.h>
#include <windows.h>
#include <winternl.h>
#define CRC_SEED 0xdeadbeef
//refrain from making this an ascii char
#define FLAG_CHAR 0x69
//crc32 impl. credits rosettacode
uint32_t crc32_my(const char *buf){
    size_t len = strnlen(buf, 50);
    static uint32_t table[256];
    static int have_table = 0;
    uint32_t rem;
    uint8_t octet;
    int i, j;
    const char *p, *q;
    if (have_table == 0) {
        for (i = 0; i < 256; i++) {
            rem = i;
            for (j = 0; j < 8; j++) {
                if (rem & 1) {
                    rem >>= 1;
                    rem ^= 0xedb88320;
                } else
                    rem >>= 1;
            }
            table[i] = rem;
        }
        have_table = 1;
    }
    uint32_t crc = CRC_SEED;
    crc = ~crc;
    q = buf + len;
    for (p = buf; p < q; p++) {
        octet = *p;
        crc = (crc >> 8) ^ table[(crc & 0xff) ^ octet];
    }
    return ~crc;
}

//lookup address by crc32
char* hashaddr(HMODULE libraryBase, DWORD hash, void** addr){
    PDWORD functionAddress = (PDWORD)0;

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)libraryBase;
    PIMAGE_NT_HEADERS imageNTHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)libraryBase + dosHeader->e_lfanew);
    
    DWORD_PTR exportDirectoryRVA = imageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    
    PIMAGE_EXPORT_DIRECTORY imageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)libraryBase + exportDirectoryRVA);
    
    PDWORD addresOfFunctionsRVA = (PDWORD)((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfFunctions);
    PDWORD addressOfNamesRVA = (PDWORD)((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfNames);
    PWORD addressOfNameOrdinalsRVA = (PWORD)((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfNameOrdinals);

    for (DWORD i = 0; i < imageExportDirectory->NumberOfFunctions; i++){
        DWORD functionNameRVA = addressOfNamesRVA[i];
        DWORD_PTR functionNameVA = (DWORD_PTR)libraryBase + functionNameRVA;
        char* functionName = (char*)functionNameVA;
        DWORD_PTR functionAddressRVA = 0;
        DWORD functionNameHash = crc32_my(functionName);
        if (functionNameHash == hash){
            functionAddressRVA = addresOfFunctionsRVA[addressOfNameOrdinalsRVA[i]];
            functionAddress = (PDWORD)((DWORD_PTR)libraryBase + functionAddressRVA);
            *addr = functionAddress;
            return functionName;
        }
    }
    return NULL;
}
//walk peb to find the dll. this because we didnt fix iat yet, cant use GetModuleHandleA
void* getDllAddr(const wchar_t * DllNameToSearch){
    PLDR_DATA_TABLE_ENTRY pDataTableEntry = 0;
    PVOID DLLAddress = 0;
    PPEB pPEB = (PPEB) __readgsqword(0x60);
    PPEB_LDR_DATA pLdr = pPEB->Ldr;
    PLIST_ENTRY AddressFirstPLIST = &pLdr->InMemoryOrderModuleList;
    PLIST_ENTRY AddressFirstNode = AddressFirstPLIST->Flink;
    for (PLIST_ENTRY Node = AddressFirstNode; Node != AddressFirstPLIST ;Node = Node->Flink){
        Node = Node - 1;
        pDataTableEntry = (PLDR_DATA_TABLE_ENTRY)Node;
        wchar_t * FullDLLName = (wchar_t *)pDataTableEntry->FullDllName.Buffer;
        for(int size = wcslen(FullDLLName), cpt = 0; cpt < size ; cpt++){
            FullDLLName[cpt] = tolower(FullDLLName[cpt]);
        }
        if(wcsstr(_wcslwr(FullDLLName), DllNameToSearch) != NULL){
            DLLAddress = (PVOID)pDataTableEntry->DllBase;
            return DLLAddress;
        }
        Node = Node + 1;
    }

    return DLLAddress;
}
//fix hashed iat
void* resolveImports(void* imageBase){
    PIMAGE_DOS_HEADER dosHeaders = (PIMAGE_DOS_HEADER)imageBase;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)imageBase + dosHeaders->e_lfanew);

    PIMAGE_IMPORT_DESCRIPTOR importDescriptor = NULL;
    IMAGE_DATA_DIRECTORY importsDirectory = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(importsDirectory.VirtualAddress + (DWORD_PTR)imageBase);
    LPCSTR libraryName = NULL;
    HMODULE library = NULL;
    while (importDescriptor->Name != 0){
        libraryName = (LPCSTR)(unsigned long long)importDescriptor->Name + (DWORD_PTR)imageBase;
        size_t cSize = strlen(libraryName)+1;
        wchar_t* wc = calloc(cSize, sizeof(wchar_t));
        mbstowcs(wc, libraryName, cSize);
        library = getDllAddr(_wcslwr(wc));
        free(wc);
        if (library && strcmp(libraryName, "msvcrt.dll") != 0){
            PIMAGE_THUNK_DATA originalFirstThunk = NULL, firstThunk = NULL;
            originalFirstThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)imageBase + importDescriptor->OriginalFirstThunk);
            firstThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)imageBase + importDescriptor->FirstThunk);
            PIMAGE_THUNK_DATA mft = originalFirstThunk;
            //recover shoved bytes
            DWORD datum;
            memcpy(&datum, ((unsigned char*)&((mft+1)->u1.AddressOfData)) + 4, 4);
            memset(((unsigned char*)&((mft+1)->u1.AddressOfData)) + 4, 0, 4);
            mft->u1.AddressOfData = datum;
            while (originalFirstThunk->u1.AddressOfData != 0){
                unsigned char* fname = (unsigned char*)((DWORD_PTR)imageBase + originalFirstThunk->u1.AddressOfData);
                //hash resolution
                if(fname[3] == FLAG_CHAR && fname[0] == 0 && fname[1] == 0){
                    void* addr = 0;
                    DWORD hash = 0;
                    memcpy(&hash, fname+4, 4);
                    char* name = hashaddr(library, hash, &addr);
                    if(name!=NULL){
                        firstThunk->u1.Function = (unsigned long long)addr;
                        memcpy(fname, fname+8, 2);
                        memcpy(fname+2, name, strlen(name)+1);
                    }
                }
                originalFirstThunk++;
                firstThunk++;
            }
        }

        importDescriptor++;
    }
}
void* GetImageBase(){
    PPEB pPEB = (PPEB) __readgsqword(0x60);
    PPEB_LDR_DATA pLdr = pPEB->Ldr;
    PLIST_ENTRY AddressFirstPLIST = &pLdr->InMemoryOrderModuleList;
    return ((PLDR_DATA_TABLE_ENTRY)(AddressFirstPLIST->Flink-1))->DllBase;
}
int main();
//hash iat
int main2(){
    LPVOID memimg = GetModuleHandleA(NULL);
    PIMAGE_DOS_HEADER dosHeaders = (PIMAGE_DOS_HEADER)memimg;
    PIMAGE_NT_HEADERS ntHeaders0 = (PIMAGE_NT_HEADERS)((DWORD_PTR)memimg + dosHeaders->e_lfanew);
    
    //duplicate image in mem
    PVOID imageBase = calloc(ntHeaders0->OptionalHeader.SizeOfImage, 1);    
    memcpy(imageBase, memimg, ntHeaders0->OptionalHeader.SizeOfImage);
    
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)imageBase + dosHeaders->e_lfanew);

    PIMAGE_IMPORT_DESCRIPTOR importDescriptor = NULL;
    IMAGE_DATA_DIRECTORY importsDirectory = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(importsDirectory.VirtualAddress + (DWORD_PTR)imageBase);
    LPCSTR libraryName = NULL;
    HMODULE library = NULL;
    PIMAGE_IMPORT_BY_NAME functionName = NULL; 
    unsigned char nops[5] = {0};
    memset(nops, 0x90, 5);
    unsigned long long endmain2 = 0;
    for(int i=0;i<1000;i++) if(memcmp((&main2)+i, nops, 5) == 0) endmain2 = i;
    //remove this function in the output file
    if(endmain2 != 0)
        memset((void*)((unsigned long long)&main2 - (unsigned long long)memimg + (unsigned long long)imageBase), 0x90, endmain2);
    while (importDescriptor->Name != 0){
        libraryName = (LPCSTR)(unsigned long long)importDescriptor->Name + (DWORD_PTR)imageBase;
        library = GetModuleHandleA(libraryName);
        if (library && strcmp(libraryName, "msvcrt.dll") != 0){
            PIMAGE_THUNK_DATA originalFirstThunk = NULL;
            originalFirstThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)imageBase + importDescriptor->OriginalFirstThunk);
            PIMAGE_THUNK_DATA oft = originalFirstThunk;
            //do hashing
            while (originalFirstThunk->u1.AddressOfData != 0){
                functionName = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)imageBase + originalFirstThunk->u1.AddressOfData);
                unsigned int hash = crc32_my(functionName->Name);
                unsigned short thunk = *((unsigned short*)functionName);
                unsigned char* fname = (unsigned char*)functionName;
                memset(fname, 0, strlen(functionName->Name) + 2);
                fname[3] = FLAG_CHAR;
                memcpy(fname+4, &hash, 4);
                memcpy(fname+8, &thunk, 2);
                originalFirstThunk++;
            }
            //we pack the first AddressOfData into the second. because we only rly need 4 bytes (no one ever uses the full 8 unless your program is HUGE)
            //this is needed to make windows happy so that it dont fail to resolve your dlls and cry about it
            DWORD data = oft->u1.AddressOfData;
            oft->u1.AddressOfData = 0;
            oft++;
            memcpy(((unsigned char*)&(oft->u1.AddressOfData)) + 4, &data, 4);
        }
        importDescriptor++;
    }
    //dump to disk
    {
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)imageBase;
        PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)imageBase + dosHeader->e_lfanew);

        PVOID localImage = calloc(ntHeader->OptionalHeader.SizeOfImage, 1);    
        memcpy(localImage, imageBase, ntHeader->OptionalHeader.SizeOfHeaders);
        PIMAGE_NT_HEADERS ntHeader2 = (PIMAGE_NT_HEADERS)((DWORD_PTR)localImage + dosHeader->e_lfanew);

        ntHeader2->OptionalHeader.AddressOfEntryPoint = (unsigned long long)&main - (unsigned long long)memimg;
        int sumsz = ntHeader->OptionalHeader.SizeOfHeaders;
        for (int count = 0; count < ntHeader->FileHeader.NumberOfSections; count++){
            PIMAGE_SECTION_HEADER SectionHeader = (PIMAGE_SECTION_HEADER)((DWORD64)localImage + dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS64) + (count * 40));
            memcpy((LPVOID)((DWORD64)localImage + SectionHeader->PointerToRawData), (LPVOID)((DWORD64)imageBase + SectionHeader->VirtualAddress), SectionHeader->SizeOfRawData);
            sumsz += SectionHeader->SizeOfRawData;
        }
        
        HANDLE hFile = CreateFileA("output.exe", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, NULL);
        DWORD bytesWritten;
        WriteFile(hFile, localImage, sumsz, &bytesWritten, NULL);
        CloseHandle(hFile);
        free(localImage);
    }
    free(imageBase);
    printf("great success\n");
    //function end marker
    asm("nop; nop; nop; nop; nop");
    return 0;
}
