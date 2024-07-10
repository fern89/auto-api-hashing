# Auto API hashing
Fully automatic Windows API hashing in C

![image](https://github.com/fern89/auto-api-hashing/assets/139056562/bf555f8b-7501-4e71-9755-7c915eb99db5)

## Problem
Existing Windows API hashing implementations typically require use of C++ (consteval is very useful), and the manual definitions of function declarations. Which is very troublesome.

## My solution
Using this method, we automate everything. On first run, the exe will read its IAT, and replace every name with its hash (and some metadata) (prefixed with a null byte to prevent anything from showing up in PE analysis tools). Then we dump to disk, write to `output.exe`

![image](https://github.com/fern89/auto-api-hashing/assets/139056562/b98511fc-9e94-49fa-a909-a8244026ead4)


Then, on subsequent runs, we will walk the IAT and find our hashed functions, then replace and resolve them manually. This gives you basically all the benefits of API hashing, with basically none of the drawbacks (manual function declaration, manual hashing if no C++ consteval).

### How to use
Step 1: Run `x86_64-w64-mingw32-gcc self.c -Wl,-emain2 -s -Os` (we change main function for convenience)

Step 2: Run `a.exe` to perform the actual hashing

Step 3: Run `output.exe` to run your actual code


### Drawbacks
1. The DLL imports are not removed, unlike the standard `LoadLibraryA` + `GetProcAddress` methods. But usually we don't hash the dll name anyways, so it's not too bad

## Credits
To https://www.ired.team/offensive-security/defense-evasion/windows-api-hashing-in-malware for the skeleton code

## Note
Note that hash collisions ARE possible, and may occur. I have already checked through kernel32, user32, and ntdll for collisions and have not found any, but it is definitely possible.
