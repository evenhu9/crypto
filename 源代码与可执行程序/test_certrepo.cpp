#include"PKI.h"
#include<NTL/ZZ.h>
#include<sstream>
#include<fstream>
using namespace std;
using namespace NTL;

int test_certrepo() {
	Cert_Repo CR;
	CA CA_root("CA_root");
	CA_root.makeCertificate2(CA_root);
	CR.addCertificate(CA_root, "CA_root");
	CA CA1("CA1");
	CA_root.makeCertificate2(CA1);
	CR.addCertificate(CA1, "CA_root");
	CA CA2("CA2");
	CA_root.makeCertificate2(CA2);
	CR.addCertificate(CA2, "CA_root");

	USER Alice("Alice");
	USER Bob("Bob");
	USER Eve("Eve");
	Alice.callCertificate(CA1);
	Bob.callCertificate(CA1);
	Eve.callCertificate(CA2);
	CR.addCertificate(Alice, "CA1");
	CR.addCertificate(Bob, "CA1");
	CR.addCertificate(Eve, "CA2");
	
	ifstream file("message.txt", ios::in);
	ZZ x;
	file >> x;
	Alice.sig.rsa.GenerateKey();
	Bob.sig.rsa.setPublicKey(Alice.sig.rsa.GetPublicKey());
	ZZ sign = Alice.sig.sig(x);

	ofstream path_file("path.txt", ios::out);
	if (!path_file.is_open())
		cout << "sign fail" << endl;
	vector<string> path;
	cout << "Bob search Alice's certificate path" << endl;
	path = CR.queryCertificatePath("Alice");
	for (int i = 0; i < path.size(); i++) {
         path_file << path[i]<<endl;
	}
	path_file.close();

	cout << "Bob verify Alice's certificate path" << endl;
	if (CR.verifyCertificate(path, Alice.ID)) {
		cout << "certificate path right" << endl;
		bool ver = Bob.sig.ver(x, sign);
		if (ver)
			cout << "pass" << endl;
		else
			cout << "fail" << endl;
	}
	return true;
}