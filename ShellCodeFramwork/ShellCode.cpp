#include "stdafx.h"
#include "ShellCode.h"

#define offsetof(s,m) ((size_t)&reinterpret_cast<char const volatile&>((((s*)0)->m)))

void CShellCode::GetPEB()
{
    PEB* p;

    __asm
    {
        mov eax, fs:[30h]
        mov p, eax
    }

    pPeb = p;
}

unsigned long CShellCode::GetHash(const char * str)
{
    unsigned long dwHash = 0;

    if (str == nullptr)
    {
        goto _exit;
    }

    // GetHash
    while (*str)
    {
        dwHash = (dwHash >> 13) | (dwHash << (32 - 13));   // ROR dwHash, 13
        dwHash += (*str >= 'a' ? *str - ('a' - 'A') : *str);
        str++;
    }

_exit:
    return dwHash;
}

unsigned long CShellCode::GetFunctionHash(const char * szModuleName, const char * szFuncName)
{
    return GetHash(szModuleName) + GetHash(szFuncName);
}

LDR_DATA_TABLE_ENTRY * CShellCode::GetLDRDataTableEntry(const LIST_ENTRY * ptr)
{
    int iListEntryOffset = offsetof(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
    return (LDR_DATA_TABLE_ENTRY*)((BYTE*)ptr - iListEntryOffset);
}

void * CShellCode::GetFuncAddressByHash(unsigned long dwHash)
{
    LIST_ENTRY* pFirst = nullptr;
    LIST_ENTRY* ptr = nullptr;
    void* pFuncAddress = nullptr;

    if (pPeb == nullptr)
    {
        GetPEB();
    }

    pFirst = pPeb->Ldr->InMemoryOrderModuleList.Flink;
    ptr = pFirst;

    do
    {
        LDR_DATA_TABLE_ENTRY* pLdrDataTableEntry = GetLDRDataTableEntry(ptr);
        ptr = ptr->Flink;

        BYTE* BaseAddress = (BYTE*)pLdrDataTableEntry->DllBase;
        if (!BaseAddress)
        {
            continue;
        }

        IMAGE_DOS_HEADER* pDosHeader = (IMAGE_DOS_HEADER*)BaseAddress;
        IMAGE_NT_HEADERS* pNtHeader = (IMAGE_NT_HEADERS*)(BaseAddress + pDosHeader->e_lfanew);
        DWORD dwIedRVA = pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        if (!dwIedRVA)
        {
            continue;
        }

        IMAGE_EXPORT_DIRECTORY* pIed = (IMAGE_EXPORT_DIRECTORY*)(BaseAddress + dwIedRVA);
        char* szModuleName = (char*)(BaseAddress + pIed->Name);

        DWORD* pNameRVAs = (DWORD*)(BaseAddress + pIed->AddressOfNames);
        for (DWORD i = 0; i < pIed->NumberOfNames; i++)
        {
            char* szFuncName = (char*)(BaseAddress + pNameRVAs[i]);
            if (dwHash == GetFunctionHash(szModuleName, szFuncName))
            {
                WORD wOrdinal = ((WORD*)(BaseAddress + pIed->AddressOfNameOrdinals))[i];
                pFuncAddress = BaseAddress + ((DWORD*)(BaseAddress + pIed->AddressOfFunctions))[wOrdinal];
                break;
            }
        }

    } while (ptr != pFirst);

    return pFuncAddress;
}

void * CShellCode::GetAPIAddress(const char * szModuleName, const char * szFuncName)
{
    unsigned long hModule = LoadLibraryA(szModuleName);
    FARPROC pFunc = nullptr;

    if (hModule != 0)
    {
        pFunc = GetProcAddress(hModule, szFuncName);
    }

    return pFunc;
}

void * CShellCode::memset(void * s, int c, size_t n)
{
    const unsigned char uc = c;
    unsigned char *su;

    for (su = (unsigned char*)s; 0 < n; ++su, --n)
    {
        *su = uc;
    }

    return s;
}

CShellCode::CShellCode()
{
    GetPEB();

    char szKernel32Dll[] = { 'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l', 0 };
    char szLoadLibraryA[] = { 'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'A', 0 };
    char szGetProcAddress[] = { 'G', 'e', 't', 'P', 'r', 'o', 'c', 'A', 'd', 'd', 'r', 'e', 's', 's', 0 };

    LoadLibraryA = (LOADLIBRARYA)GetFuncAddressByHash(GetFunctionHash(szKernel32Dll, szLoadLibraryA));
    GetProcAddress = (GETPROCADDRESS)GetFuncAddressByHash(GetFunctionHash(szKernel32Dll, szGetProcAddress));
}


CShellCode::~CShellCode()
{
}

void CShellCode::Run()
{
}
