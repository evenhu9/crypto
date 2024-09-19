#define _CRT_SECURE_NO_WARNINGS
#include<iostream>
using namespace std;

int test_RSA();
int test_sig();
int test_Certificate();
int test_certrepo();
int main(){
	int a;
	cout << "--------------------------------" << endl;
	cout << "* MENU" << endl;
	cout << "* 1.RSA encode/decode" << endl;
	cout << "* 2.RSA sign" << endl;
	cout << "* 3.simple certificate" << endl;
	cout << "* 4.PKI" << endl;
	cout << "* 5.quit" << endl;
	cout << "--------------------------------" << endl;
	cout << "please choose one to continue:";
	while (cin >> a) {
		switch (a) {
		case 1:
			test_RSA();
			break;
		case 2:
			test_sig();
			break;
		case 3:
			test_Certificate();
			break;
		case 4:
			test_certrepo();
			break;
		case 5:
			return 0;
		default:
			break;
		}
		cout << "please choose one to continue:";
	}
	return 0;
}