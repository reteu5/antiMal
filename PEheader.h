#pragma once
#include <windows.h>
#include <iostream>
#include <stdio.h>

class PEheader {
private:
    HANDLE hFile = NULL;
    HANDLE hMapping = NULL;
    LPVOID hMapping = NULL;
    LPVOID lpBase = NULL;
    IMAGE_DOS_HEADER* dosHeader = NULL;
    IMAGE_NT_HEADERS32* ntHeader = NULL;

public:
    PEheader(char* argv[]) {
        this->hFile = CreateFileA(argv[1], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        this->hMapping = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
        this->hMapping = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
        this->lpBase = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
        this->dosHeader = (IMAGE_DOS_HEADER*)lpBase;
        this->ntHeader = (IMAGE_NT_HEADERS32*)((BYTE*)lpBase + dosHeader->e_lfanew);
    }
    void checkAvailability(int argc, char* argv[]) {
        if (argc < 2) {
            cout << "Usage: " << argv[0] << "<executable file name>" << endl;
            exit(1);
        }
        if (this->hFile == INVALID_HANDLE_VALUE) {
            cout << "Error: Cannot open file" << argv[1] << endl;
            exit(1);
        }
        if (this->hMapping == NULL) {
            CloseHandle(this->hFile);
            cout << "Error: Cannot create file mapping\n" << endl;
            exit(1);
        }
        if (this->lpBase == NULL) {
            CloseHandle(this->hMapping);
            CloseHandle(this->hFile);
            cout << "Error: Cannot map view of file\n" << endl;
            exit(1);
        }
        if (this->dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            cout << "Error: Invalid DOS header signature\n" << endl;
            UnmapViewOfFile(this->lpBase);
            CloseHandle(this->hMapping);
            CloseHandle(this->hFile);
            exit(1);
        }
        if (this->ntHeader->Signature != IMAGE_NT_SIGNATURE) {
            cout << "Error: Invalid NT header signature" << endl;
            UnmapViewOfFile(this->lpBase);
            CloseHandle(this->hMapping);
            CloseHandle(this->hFile);
            exit(1);
        }
    }

    void executePEParser() {
        cout << "PE header information:" << endl;
        cout << "  Machine type: 0x" << this->ntHeader->FileHeader.Machine << endl;
        cout << "  Number of sections: " << this->ntHeader->FileHeader.NumberOfSections << endl;
        cout << "  Timestamp: 0x" << this->ntHeader->FileHeader.TimeDateStamp << endl;
        cout << "  Entry point address: 0x" << this->ntHeader->OptionalHeader.AddressOfEntryPoint << endl;
        cout << "  Image base address: 0x" << this->ntHeader->OptionalHeader.ImageBase << endl;
        cout << "  Section alignment: " << this->ntHeader->OptionalHeader.SectionAlignment << endl;
        cout << "  File alignment: " << this->ntHeader->OptionalHeader.FileAlignment << endl;
        cout << "  Size of image: " << this->ntHeader->OptionalHeader.SizeOfImage << endl;
        cout << "  Size of headers: " << this->ntHeader->OptionalHeader.SizeOfHeaders << endl;
        cout << "  Subsystem: " << this->ntHeader->OptionalHeader.Subsystem << endl;
        cout << "  Number of RVA and sizes: " << this->ntHeader->OptionalHeader.NumberOfRvaAndSizes << endl;
    }

    ~PEheader() {
        UnmapViewOfFile(this->lpBase);
        CloseHandle(this->hMapping);
        CloseHandle(this->hFile);
    }
};