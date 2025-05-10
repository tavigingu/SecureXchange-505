#pragma once
#define _CRT_SECURE_NO_WARNINGS
#pragma warning(disable : 4996)
#include <openssl/ec.h>
#include <openssl/opensslv.h>
#include <openssl/pem.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h> 
#include <openssl/cmac.h>
#include <openssl/kdf.h>         
#include <openssl/rand.h>                 
#include <openssl/ossl_typ.h>
#include <openssl/params.h>

class KeyGenerator
{
public:
	static KeyGenerator& getInstance() {
		static KeyGenerator instance; 
		return instance;
	}

	void generateECKeyPair(const char* keyPublicFilename, const char* keyPrivateFilename, const char* password);

private:
	KeyGenerator() {}  // constructor privat
	KeyGenerator(const KeyGenerator&) = delete;
	KeyGenerator& operator=(const KeyGenerator&) = delete;

	unsigned char* generatePBKDF2Key(long time_diff);
	long calculateTimeDifference();
	unsigned char* generateGMACAuthTag(unsigned char* data, long data_len, const unsigned char* key);
};

