#include<string>
#include<iostream>
#include<fstream>
#include<NTL/ZZ.h>
#include"RSA.h"
using namespace NTL;

#define IS_PRIME 1
#define NOT_PRIME 0
#define PRIME_TEST_ROUND 5

RSA::RSA(const RSA& rsa)
{
	this->key = rsa.key;
	this->pub = rsa.pub;
}
void RSA::operator=(const RSA& rsa)
{
	this->key = rsa.key;
	this->pub = rsa.pub;
}
void RSA::setPublicKey(Public_key pub)
{
	this->pub = pub;
}
bool RSA::GenerateKey(int key_len){
	ZZ p, q;
	int l=0;
	if (key_len != PRIME_LEN1 && key_len != PRIME_LEN2) {//检测密钥长度是否合理
		std::cout << "key length is not support" << std::endl;
		return false;
	}
	else
		l = key_len;
	//使用NTL库中的素数生成函数
	GenPrime(p, l);
	GenPrime(q, l);
	//计算𝜑(𝑛)
	ZZ phi;
	mul(phi, p - 1, q - 1);
	ZZ a, b, d;
	//获得随机素数b
	do {
		RandomBnd(b,phi);
		GCD(d, b, phi);
	} while (b <= 1 || d != 1);
	//𝑏 𝑚𝑜𝑑 𝜑(𝑛)的逆元�
	InvMod(a, b, phi);
	ZZ n;//求n
	mul(n, p, q);
	Public_key pub = { n,b };
	Private_key pri = { p,q,a };
	this->key.pub = pub;
	this->key.pri = pri;
	return true;
}
ZZ RSA::encrypt(ZZ x) const
{
	return PowerMod(x, this->pub.b, this->pub.n);
}
ZZ RSA::decrypt(ZZ y) const
{
	return PowerMod(y, this->key.pri.a, this->key.pub.n);
}

