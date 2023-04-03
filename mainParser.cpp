#include "PEparser.h"
#include <windows.h>
#include <iostream>

using namespace std;



int main(int argc, char* argv[]) {
    if (argc < 2) {
        cout << "Usage: " << argv[0] << " <executable PE file's name>" << endl;
        exit(1);
    }

    PEheader peFile = PEheader(argv);

    if (peFile.checkAvailability(argc, argv)) {
        //print DOSHeader
        // 
        //32bit 64bit check
        //print NTHeader
    }


    return 0;
}
