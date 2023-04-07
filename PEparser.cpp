#include <iostream>
#include <format>
#include "PEParser.h"
using namespace PEParse;

PEParser::~PEParser() {
    clean();
};

void PEParser::clean() {
    if (m_peFileMapping != NULL)
    {
        UnmapViewOfFile(m_peBaseAddress);
        CloseHandle(m_peFileMapping);
    }
    if (m_peFileHandle != NULL)
    {
        CloseHandle(m_peFileHandle);
    }
    m_peDosHeader = NULL;
    m_peBaseAddress = NULL;
    m_peFilePath.clear();
};

void PEParser::debug(tstring debugMsg) {
    OutputDebugStringT(debugMsg.c_str());
    OutputDebugStringT(_T("\n"));
};

BOOL PEParser::parsePE(tstring filePath) {
    BOOL flag = FALSE;
    tstring debugmessage = _T("");

    clean();
    m_peFilePath = filePath;
    debugmessage = _T("Inputted File Path : ");
    debugmessage.append(m_peFilePath);
    debug(debugmessage);

    m_peFileHandle = CreateFile(m_peFilePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (m_peFileHandle == INVALID_HANDLE_VALUE) {
        debug(_T("Error: Failed to open file.\n"));
    }
    else {
        m_peFileMapping = CreateFileMapping(m_peFileHandle, NULL, PAGE_READONLY, 0, 0, NULL);
        if (m_peFileMapping == NULL) {
            CloseHandle(m_peFileHandle);
            m_peFileHandle = NULL;
            debug(_T("Error: Failed to create a file mapping.\n"));
        }
        else
        {
            m_peBaseAddress = MapViewOfFile(m_peFileMapping, FILE_MAP_READ, 0, 0, 0);
            if (m_peBaseAddress != NULL)
            {
                flag = TRUE;
            }
            else
            {
                CloseHandle(m_peFileMapping);
                CloseHandle(m_peFileHandle);
                m_peFileMapping = NULL;
                m_peFileHandle = NULL;
                debug(_T("Error: Cannot map view of file.\n"));
            }
        }
    }
    return flag;
};

BOOL PEParser::printDosHeader() {
    BOOL flag = FALSE;
    m_peDosHeader = (IMAGE_DOS_HEADER*)m_peBaseAddress;
    if (m_peDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        debug(_T("Error: Invalid DOS header signature\n"));
    }
    else
    {
        tcout << _T("DOS signature:0x") << (WORD)m_peDosHeader->e_magic << std::endl;
        flag = TRUE;
    }
    return TRUE;
};

BOOL PEParser::printNTHeader() {
    BOOL flag = FALSE;
    IMAGE_NT_HEADERS32* ntHeader = (IMAGE_NT_HEADERS32*)((BYTE*)m_peBaseAddress + (WORD)m_peDosHeader->e_lfanew);

    if (ntHeader->Signature != IMAGE_NT_SIGNATURE) {
        debug(_T("Error: Invalid NT header signature\n"));
    }
    else
    {
        if ((WORD)ntHeader->FileHeader.Machine == IMAGE_FILE_MACHINE_I386)
        {
            // 32bit PE
            printNTHeader32();
            flag = TRUE;
        }
        else
        {
            // 64bit PE
            printNTHeader64();
            flag = TRUE;
        }
    }
    return flag;
};

void PEParser::printNTHeader32() {
    IMAGE_NT_HEADERS32* ntHeader = (IMAGE_NT_HEADERS32*)((BYTE*)m_peBaseAddress + (WORD)m_peDosHeader->e_lfanew);

    tcout << _T("Machine type:0x") << (WORD)ntHeader->FileHeader.Machine << std::endl;
    tcout << _T("Number of sections:0x") << (WORD)ntHeader->FileHeader.NumberOfSections << std::endl;
    tcout << _T("Timestamp:0x") << (DWORD)ntHeader->FileHeader.TimeDateStamp << std::endl;
    tcout << _T("Entry point address:0x") << (DWORD)ntHeader->OptionalHeader.AddressOfEntryPoint << std::endl;
    tcout << _T("Image base address:0x") << (DWORD)ntHeader->OptionalHeader.ImageBase << std::endl;
    tcout << _T("Section alignment:0x") << (DWORD)ntHeader->OptionalHeader.SectionAlignment << std::endl;
    tcout << _T("File alignment:0x") << (DWORD)ntHeader->OptionalHeader.FileAlignment << std::endl;
    tcout << _T("Size of image:0x") << (DWORD)ntHeader->OptionalHeader.SizeOfImage << std::endl;
    tcout << _T("Size of headers:0x") << (DWORD)ntHeader->OptionalHeader.SizeOfHeaders << std::endl;
    tcout << _T("Subsystem:0x") << (WORD)ntHeader->OptionalHeader.Subsystem << std::endl;
    tcout << _T("Number of RVA and sizes:0x") << (DWORD)ntHeader->OptionalHeader.NumberOfRvaAndSizes << std::endl;
};

void PEParser::printNTHeader64() {
    IMAGE_NT_HEADERS64* ntHeader = (IMAGE_NT_HEADERS64*)((BYTE*)m_peBaseAddress + (((IMAGE_DOS_HEADER*)m_peBaseAddress)->e_lfanew));
    tcout << _T("Machine type:0x") << (WORD)ntHeader->FileHeader.Machine << std::endl;
    tcout << _T("Number of sections:0x") << (WORD)ntHeader->FileHeader.NumberOfSections << std::endl;
    tcout << _T("Timestamp:0x") << (DWORD)ntHeader->FileHeader.TimeDateStamp << std::endl;
    tcout << _T("Entry point address:0x") << (DWORD)ntHeader->OptionalHeader.AddressOfEntryPoint << std::endl;
    tcout << _T("Image base address:0x") << (ULONGLONG)ntHeader->OptionalHeader.ImageBase << std::endl;
    tcout << _T("Section alignment:0x") << (DWORD)ntHeader->OptionalHeader.SectionAlignment << std::endl;
    tcout << _T("File alignment:0x") << (DWORD)ntHeader->OptionalHeader.FileAlignment << std::endl;
    tcout << _T("Size of image:0x") << (DWORD)ntHeader->OptionalHeader.SizeOfImage << std::endl;
    tcout << _T("Size of headers:0x") << (DWORD)ntHeader->OptionalHeader.SizeOfHeaders << std::endl;
    tcout << _T("Subsystem:0x") << (WORD)ntHeader->OptionalHeader.Subsystem << std::endl;
    tcout << _T("Number of RVA and sizes:0x") << (DWORD)ntHeader->OptionalHeader.NumberOfRvaAndSizes << std::endl;
};
