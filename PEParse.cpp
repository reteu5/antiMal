#include <windows.h>
#include <stdio.h>
#include <iostream>
#include <antiMal/PEParse.h>

using namespace std;



int main(int argc, char* argv[]) {

    PEheader peFile = PEheader(argv);
    peFile.checkAvailability(argc, argv);
    peFile.executePEParser();
    //peFile.~PEheader();



    return 0;
}