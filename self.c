#include <stdio.h>
#include <string.h>
#include <windows.h>
#include "hasher.h"
int main(){
    LPVOID imageBase = GetModuleHandleA(NULL);
    resolveImports(imageBase);
    Sleep(1000);
    MessageBoxA(NULL, "ok", "ok", MB_OK);
}