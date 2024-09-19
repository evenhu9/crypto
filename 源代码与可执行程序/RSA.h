#ifndef RSA_H
#define RSA_H
#include<NTL/ZZ.h>
using namespace NTL;

const int PRIME_LEN1 = 512;
const int PRIME_LEN2 = 1024;
struct Public_key{
	ZZ n,b;
};
struct Private_key{
	ZZ p,q,a;
};
class RSA {
public:
	Public_key pub;//用于加密别人的公钥
public:
	RSA() {};
	RSA(const RSA&);
	void operator=(const RSA&);
	void setPublicKey(Public_key);
	bool GenerateKey(int l=PRIME_LEN1);
	ZZ encrypt(ZZ) const;
	ZZ decrypt(ZZ) const;
	Public_key GetPublicKey() const { return this->key.pub; }
	Private_key GetPrivateKey() const { return this->key.pri; }
private:
	struct Key{
		Public_key pub;
		Private_key pri;
	};
	Key key;
};
#endif // !RSA
