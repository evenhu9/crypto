#define _CRT_SECURE_NO_WARNINGS
#ifndef PKI_H
#define PKI_H
#include<string>
#include<vector>
#include <map>
#include<sstream>
#include"RsaSig.h"
using namespace std;
class CA;
class USER {
	friend class CA;
	friend class Cert_Repo;
public:
	USER() {}
	USER(const string& id) { ID = id; }
	void operator=(const USER&);
	string getID() const { return ID; }

	void callCertificate(CA&);
	bool verifyCertificate(const string&, const CA&);
	string getCertificate() const { return Certificate; }
	void writeLog(const string&, const string&, bool);
public:
	RsaSig sig;
	string Certificate;
	string ID;
};

class CA {
	friend class Cert_Repo;
public:
	CA() {};
	CA(const string&);
	CA(int, const string&);
	void operator=(const CA&);
	string makeCert(USER&)const;
	void makeCertificate2(CA& ca);
	string getID() const { return ID; }
	Public_key getPubCA() const { return this->sig.rsa.GetPublicKey(); }

private:
	RsaSig sig;
	string ID;
	string Certificate;
	int primeLen;
};


class Cert_Repo {
public:
	void addCertificate(const CA& ca, const string& pri_ca);
	void addCertificate(const USER& cl, const string& ca);
	bool verifyCertificate(vector<string>& path, const string& ownerID) const;
	vector<string> queryCertificatePath(const std::string& ownerID) const;

private:
    map<string, string> caCertMap;  // Client/CA ID -> CA ID
    map<string, string> certificates; // ֤ID -> ֤certificate
};

#endif // PKI_H