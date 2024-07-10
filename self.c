#include <stdio.h>
#include <string.h>
#include <windows.h>
#include "hasher.h"
int main(){
    void* imageBase = GetImageBase();
    resolveImports(imageBase);
    //do not add any code above this line
    Sleep(1000);
    MessageBoxA(NULL, "MESSAGE", "BOX", MB_OK);
}
