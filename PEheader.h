#pragma once
#include <windows.h>
#include <iostream>
#include <stdio.h>

class PEheader {
private:
    HANDLE hFile = NULL;
    HANDLE hMapping = NULL;
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
    void checkAvailability(int argc, char* argv[]);

    void executePEParser();

    ~PEheader() {
        UnmapViewOfFile(this->lpBase);
        CloseHandle(this->hMapping);
        CloseHandle(this->hFile);
    }
};
