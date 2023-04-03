#pragma once
#include <windows.h>
#include <iostream>
#include <tchar.h>  //todo
#include <format>  //todo

typedef std::basic_string<TCHAR> tstring;
#if defined(UNICODE) || defined(_UNICODE)
    #define tcout std::wcout
    #define OutputDebugStringT OutputDebugStringW
#else
    #define tcout std::cout
    #define OutputDebugStringT OutputDebugStringA
#endif

class PEheader {
private:
    HANDLE hFile = NULL;
    HANDLE hMapping = NULL;
    LPVOID lpBase = NULL;
    IMAGE_DOS_HEADER* dosHeader = NULL;
    IMAGE_NT_HEADERS32* ntHeader = NULL;
    void printNTHeader32(void);
    void printNTHeader64(void);

protected:
    tstring m_peFilePath = _T("");
    HANDLE m_peFileHandle = NULL;
    HANDLE m_peFileMapping = NULL;
    LPVOID m_peBaseAddress = NULL;
    IMAGE_DOS_HEADER* m_peDosHeader = NULL;

public:
    PEheader(char* argv[]);
    BOOL checkAvailability(int argc, char* argv[]);
    void executePEParser();
    ~PEheader();
};
