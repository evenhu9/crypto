#include<iostream>
#include<NTL/ZZ.h>
#include<fstream>
#include"RSA.h"

#include<bitset>

using namespace std;
using namespace NTL;

int test_RSA()
{
	RSA rsa;
	int len = 512;
	ifstream file("message.txt", ios::in);
	ofstream cipher_text("cipher.txt", ios::out);
	ofstream decode_file("decode.txt", ios::out);
	ofstream key_file("key.txt", ios::out);
	if (!file.is_open())
		cout << "message fail" << endl;
	if (!cipher_text.is_open())
		cout << "cipher fail" << endl;
	if (!decode_file.is_open())
		cout << "decode fail" << endl;
	if (!key_file.is_open())
		cout << "key fail" << endl;

	string str;
	bool k;
	ZZ cipher;
	ZZ message;
	cout << "enter the length of key (512/1024):";
	cin >> len;
	file >> message;
	k = rsa.GenerateKey(len);
	if (!k)
		return false;
	Public_key pub=rsa.GetPublicKey();
	Private_key pri=rsa.GetPrivateKey();
	key_file << "public key:" << endl;
	key_file << "n,b" << endl;
	key_file << pub.n << "," << pub.b << endl;
	key_file << "private key" << endl;
	key_file << "p,q,a" << endl;
	key_file << pri.p << "," << pri.q << "," << pri.a << endl;
	cout << "private key" << endl;
	cout <<"p=" << pri.p << "\nq=" << pri.q << "\na=" << pri.a << endl;
	cout << "public key:" << endl;
	cout << "n=" << pub.n << "\nb=" << pub.b << endl;
	rsa.setPublicKey(pub);
	cipher = rsa.encrypt(message);
	cipher_text << cipher;
	message = rsa.decrypt(cipher);
	decode_file << message;
	file.close();
	cipher_text.close();
	decode_file.close();
	key_file.close();
	return true;
}