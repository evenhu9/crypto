#define _CRT_SECURE_NO_WARNINGS
#include"PKI.h"
#include<NTL/ZZ.h>
#include<sstream>
#include<fstream>
#include<math.h>
#include<time.h>
#include<direct.h>
#include<io.h>
using namespace NTL;

vector<std::string> stringSplit(const string& str, char delim);
string ZZ2str(const ZZ& zz);
ZZ str2ZZ(const string& str);
string int2str(int n);
int str2int(const string& str);

CA::CA(const string& id)
{
	primeLen = PRIME_LEN1;
	this->sig.rsa.GenerateKey();
	this->ID = id;
}

CA::CA(int len, const string& id)
{
	try {
		if (len == PRIME_LEN1 || len == PRIME_LEN2)
			primeLen = len;
		else
			throw string("prime length not allowed");
	}
	catch (string e)
	{
		cerr << e << endl;
	}
	this->sig.rsa.GenerateKey(len);
	this->ID = id;
}

string CA::makeCert(USER& user)const
{
	int pubKeyLen[2];
	user.sig.rsa.GenerateKey(primeLen);
	Public_key pub = user.sig.rsa.GetPublicKey();
	pubKeyLen[0] = ZZ2str(pub.b).length();
	pubKeyLen[1] = ZZ2str(pub.n).length();
	ZZ sig_obj = str2ZZ(user.getID() + ZZ2str(pub.b) + ZZ2str(pub.n));
	//user.pubTA = this->sig.rsa.GetPublicKey();
	Public_key pubTA = this->sig.rsa.GetPublicKey();
	ZZ s = this->sig.sig(sig_obj % pubTA.n);

	string cert =
		"Client:\n"
		+ user.getID() + "\n"
		+ "b:\n"
		+ ZZ2str(pub.b) + "\n"
		+ "n:\n"
		+ ZZ2str(pub.n) + "\n"
		+ "s:\n"
		+ ZZ2str(s) + "\n"
		+ "CA_ID:\n"
		+ this->ID + "\n"
		+ "b_len:\n"
		+ int2str(pubKeyLen[0]) + "\n"
		+ "n_len\n"
		+ int2str(pubKeyLen[1]) + "\n";

	string dir = ".\\" + user.getID();
	if (_access(dir.c_str(), 0) == -1)
		_mkdir(dir.c_str());
	string filename = ".\\" + user.getID() + "\\" + this->ID + "_cert.txt";
	ofstream fcert(filename, ios::out);
	try {
		if (!fcert.is_open())
			throw string("cert open error");
	}
	catch (string e)
	{
		cerr << e << endl;
	}
	fcert << cert;
	fcert.close();

	return cert;
}

void CA::makeCertificate2(CA& ca)
{
	int pubKeyLen[2];
	ca.sig.rsa.GenerateKey(primeLen);
	Public_key pub = ca.sig.rsa.GetPublicKey();
	pubKeyLen[0] = ZZ2str(pub.b).length();
	pubKeyLen[1] = ZZ2str(pub.n).length();


	ZZ sig_obj = str2ZZ(ca.getID() + ZZ2str(pub.b) + ZZ2str(pub.n));
	//user.pubTA = this->sig.rsa.GetPublicKey();
	Public_key pubTA = this->sig.rsa.GetPublicKey();
	ZZ s = this->sig.sig(sig_obj % pubTA.n);

	string cert =
		"CA:\n"
		+ ca.getID() + "\n"
		+ "b:\n"
		+ ZZ2str(pub.b) + "\n"
		+ "n:\n"
		+ ZZ2str(pub.n) + "\n"
		+ "s:\n"
		+ ZZ2str(s) + "\n"
		+ "PRI_CA_ID:\n"
		+ this->ID + "\n"
		+ "b_len:\n"
		+ int2str(pubKeyLen[0]) + "\n"
		+ "n_len\n"
		+ int2str(pubKeyLen[1]) + "\n";

	string dir = ".\\" + ca.getID();
	if (_access(dir.c_str(), 0) == -1)
		_mkdir(dir.c_str());
	string filename = ".\\" + ca.getID() + "\\" + this->ID + "_cert.txt";
	ofstream fcert(filename, ios::out);
	try {
		if (!fcert.is_open())
			throw string("cert open error");
	}
	catch (string e)
	{
		cerr << e << endl;
	}
	fcert << cert;
	fcert.close();
	ca.Certificate = cert;
	return;
}

void USER::callCertificate(CA& ca)
{
	this->Certificate = ca.makeCert(*this);
}

void USER::writeLog(const string& client, const string& CAname, bool is_pass)
{
	string dir = ".\\" + this->ID;
	if (_access(dir.c_str(), 0) == -1)
		_mkdir(dir.c_str());
	string filename = ".\\" + this->ID + "\\ver.log";
	ofstream log(filename, ios::out | ios::app);
	try {
		if (!log.is_open())
			throw string("log open error");
	}
	catch (string e)
	{
		cerr << e << endl;
	}

	time_t rawtime;
	struct tm* ptminfo;

	time(&rawtime);
	ptminfo = localtime(&rawtime);

	log << "--------------------" << endl;
	log << "date: " << ptminfo->tm_year + 1900 << "/" << ptminfo->tm_mon + 1 << "/" << ptminfo->tm_mday << endl;
	log << "time: " << ptminfo->tm_hour << ":" << ptminfo->tm_min << ":" << ptminfo->tm_sec << endl;
	log << "from:" << client << endl;
	log << "to: " << this->ID << endl;
	log << "TA:" << CAname << endl;
	if (is_pass)
		log << "status: pass" << endl;
	else
		log << "status: fail" << endl;
	log << "--------------------" << endl;

	log.close();
}

bool USER::verifyCertificate(const string& cert, const CA& ca)
{
	string CAname = ca.getID();
	stringstream stream(cert);
	string ID;
	getline(stream, ID);
	getline(stream, ID);

	string bstr, nstr;
	ZZ b, n;
	Public_key pub;
	getline(stream, bstr);
	getline(stream, bstr);
	getline(stream, nstr);
	getline(stream, nstr);
	b = str2ZZ(bstr);
	n = str2ZZ(nstr);
	pub.b = b;
	pub.n = n;

	string sstr;
	ZZ s;
	getline(stream, sstr);
	getline(stream, sstr);
	s = str2ZZ(sstr);

	ZZ sig_obj = str2ZZ(ID + bstr + nstr);

	Public_key pubCA = ca.getPubCA();
	this->sig.rsa.setPublicKey(pubCA);


	bool is_pass = this->sig.ver(sig_obj % pubCA.n, s % pubCA.n);
	if (is_pass)
		this->sig.rsa.setPublicKey(pub);

	writeLog(ID, CAname, is_pass);

	return is_pass;
}

void USER::operator=(const USER& client)
{
	this->Certificate = client.Certificate;
	this->ID = client.ID;
	this->sig = client.sig;
}

void CA::operator=(const CA& ca)
{
	this->ID = ca.ID;
	this->sig = ca.sig;
	this->primeLen = ca.primeLen;
}


void Cert_Repo::addCertificate(const CA& ca,const string& pri_ca) {
	certificates[ca.ID] = ca.Certificate;
	if (ca.ID != pri_ca) {
		caCertMap[ca.ID] = pri_ca;
	}
}

void Cert_Repo::addCertificate(const USER& cl,const string& ca) {
	certificates[cl.ID] = cl.Certificate;
	caCertMap[cl.ID] = ca;
}

vector<string> Cert_Repo::queryCertificatePath(const string& ownerID) const {
	vector<string> path;
	string currentID = ownerID;
	string root = "CA_root";
	if (certificates.find(currentID) == certificates.end())
		return path;
	while (currentID != root) {
		string caID = caCertMap.at(currentID);
		path.push_back(certificates.at(currentID));
		currentID = caID;
	}
	path.push_back(certificates.at(currentID));

	reverse(path.begin(), path.end());
	return path;
}

bool Cert_Repo::verifyCertificate(vector<string>& path, const string& ownerID) const {
	bool flag=true;
	string currentID = ownerID;
	string root = "CA_root";
	vector<string> temp=path;
	reverse(temp.begin(), temp.end());
	for (int i = 0; i < temp.size(); i++) {
		flag = temp[i] == certificates.at(currentID);
		if (currentID != root) {
			string caID = caCertMap.at(currentID);
			currentID = caID;
		}
	}
	return flag;
}