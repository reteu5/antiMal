#include "PEheader.h"
#include <windows.h>
#include <stdio.h>
#include <iostream>

using namespace std;



int main(int argc, char* argv[]) {

    PEheader peFile = PEheader(argv);
    peFile.checkAvailability(argc, argv);
    peFile.executePEParser();
    //peFile.~PEheader();



    return 0;
}

void PEheader::checkAvailability(int argc, char* argv[]) {
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

void PEheader::executePEParser() {
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
