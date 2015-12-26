#pragma once

#include "WinType.h"

typedef unsigned long(_stdcall *LOADLIBRARYA)(const char*);
typedef int(_stdcall *FARPROC)();
typedef FARPROC(_stdcall *GETPROCADDRESS)(unsigned long, const char*);

class CShellCode
{
private:
    PEB* pPeb;

protected:
    LOADLIBRARYA LoadLibraryA;
    GETPROCADDRESS GetProcAddress;

private:
    void GetPEB();
    unsigned long GetHash(_In_ const char* str);
    unsigned long GetFunctionHash(_In_ const char* szModuleName, _In_ const char* szFuncName);
    LDR_DATA_TABLE_ENTRY* GetLDRDataTableEntry(_In_ const LIST_ENTRY* ptr);
    void* GetFuncAddressByHash(_In_ unsigned long dwHash);

protected:
    void* GetAPIAddress(_In_ const char* szModuleName, _In_ const char* szFuncName);

public:
    CShellCode();
    ~CShellCode();

    void Run();
};

