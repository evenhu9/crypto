#include"Certificate.h"
#include<NTL/ZZ.h>
#include<sstream>
using namespace std;
using namespace NTL;

int test_Certificate() {
	TA ta("Authority");
	TA ta2("fake");
	Client Alice("Alice");
	Client Bob("Bob");
	Client Oscar("Bob");
	//Alice.callCertificate(ta);
	Bob.callCertificate(ta);
	Oscar.callCertificate(ta2);

	cout << "Alice verify Bob's Certificate" << endl;
	if (Alice.verifyCertificate(Bob.getCertificate(), ta))
		cout << "pass" << endl;
	else
		cout << "fail" << endl;

	cout << "Alice verify Oscar's Certificate" << endl;
	if (Alice.verifyCertificate(Oscar.getCertificate(), ta))
		cout << "pass" << endl;
	else
		cout << "fail" << endl;

	return true;
}