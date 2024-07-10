#include <stdio.h>
#include <inttypes.h>
#include <string.h>
#include <windows.h>
#include <winternl.h>
#define CRC_SEED 0xdeadbeef
#define FLAG_CHAR 0x69
const char* reserved[] = {"DeleteCriticalSection", "EnterCriticalSection", "GetLastError", "GetModuleHandleA", "GetStartupInfoA", "InitializeCriticalSection", "IsDBCSLeadByteEx", "LeaveCriticalSection", "MultiByteToWideChar", "SetUnhandledExceptionFilter", "TlsGetValue", "VirtualProtect", "VirtualQuery", "WideCharToMultiByte"};
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
        library = GetModuleHandleA(libraryName);
        if (library && strcmp(libraryName, "msvcrt.dll") != 0){
            
            PIMAGE_THUNK_DATA originalFirstThunk = NULL, firstThunk = NULL;
            originalFirstThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)imageBase + importDescriptor->OriginalFirstThunk);
            firstThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)imageBase + importDescriptor->FirstThunk);

            while (originalFirstThunk->u1.AddressOfData != 0){
                unsigned char* fname = (unsigned char*)((DWORD_PTR)imageBase + originalFirstThunk->u1.AddressOfData);
                if(fname[3] == FLAG_CHAR && fname[0] == 0 && fname[1] == 0){
                    void* addr = 0;
                    DWORD hash = 0;
                    memcpy(&hash, fname+4, 4);
                    char* name = hashaddr(library, hash, &addr);
                    if(name!=NULL){
                        DWORD oldProtect, oldProtect2;
                        VirtualProtect((LPVOID)(&firstThunk->u1.Function), 8, PAGE_READWRITE, &oldProtect);
                        firstThunk->u1.Function = (unsigned long long)addr;
                        VirtualProtect((LPVOID)(&firstThunk->u1.Function), 8, oldProtect, &oldProtect2);
                        VirtualProtect(fname, 50, PAGE_READWRITE, &oldProtect);
                        memcpy(fname, fname+8, 2);
                        memcpy(fname+2, name, strlen(name));
                        VirtualProtect(fname, 50, oldProtect, &oldProtect2);
                    }
                }
                ++originalFirstThunk;
                ++firstThunk;
            }
        }

        importDescriptor++;
    }
}
int main();
//hash iat
int main2(){
    LPVOID memimg = GetModuleHandleA(NULL);
    PIMAGE_DOS_HEADER dosHeaders = (PIMAGE_DOS_HEADER)memimg;
    PIMAGE_NT_HEADERS ntHeaders0 = (PIMAGE_NT_HEADERS)((DWORD_PTR)memimg + dosHeaders->e_lfanew);
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
        memset((void*)((unsigned long long)&main2 - (unsigned long long)memimg + (unsigned long long)imageBase), 0, endmain2);
    while (importDescriptor->Name != 0){
        libraryName = (LPCSTR)(unsigned long long)importDescriptor->Name + (DWORD_PTR)imageBase;
        library = GetModuleHandleA(libraryName);
        if (library && strcmp(libraryName, "msvcrt.dll") != 0){
            
            PIMAGE_THUNK_DATA originalFirstThunk = NULL, firstThunk = NULL;
            originalFirstThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)imageBase + importDescriptor->OriginalFirstThunk);
            firstThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)imageBase + importDescriptor->FirstThunk);

            while (originalFirstThunk->u1.AddressOfData != 0){
                functionName = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)imageBase + originalFirstThunk->u1.AddressOfData);
                int accept = 1;
                for(int i=0;i<(sizeof(reserved)/sizeof(char*)); i++) if(strcmp(reserved[i], functionName->Name) == 0) accept = 0;
                if(accept){
                    unsigned int hash = crc32_my(functionName->Name);
                    unsigned short thunk = *((unsigned short*)functionName);
                    unsigned char* fname = (unsigned char*)functionName;
                    memset(fname, 0, strlen(functionName->Name) + 2);
                    fname[3] = FLAG_CHAR;
                    memcpy(fname+4, &hash, 4);
                    memcpy(fname+8, &thunk, 2);
                }
                ++originalFirstThunk;
                ++firstThunk;
            }
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
