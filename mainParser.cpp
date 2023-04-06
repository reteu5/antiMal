#include <iostream>
#include "PEParser.h"

using namespace std;
using namespace PEParse;

/*int main(void) {
	PEParser peParser = PEParser();
	if (peParser.parsePE(_T("C:\Windows\System32\calc.exe"))) {
		peParser.printDosHeader();
		peParser.printNTHeader();
	}

	return 0;
};*/


int main(void) {
	PEParser peParser = PEParser();
	tstring filePath = _T("=========== INPUT DESIRED FILE PATH HERE ===========");

	tcout << _T("test string\n") << endl;
	filePath = _T("C:\\Windows\\System32\\calc.exe");
	if (peParser.parsePE(filePath) == TRUE) {
		peParser.printDosHeader();
		peParser.printNTHeader();
		tcout << filePath << endl;
	}
	tcout << _T("test string\n") << filePath << endl;

	return 0;
};
