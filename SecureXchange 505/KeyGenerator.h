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
#include "IDGenerator.h"

class KeyGenerator
{
public:
	void generateECKeyPair(const char* keyPublicFilename, const char* macFilename, const char* keyPrivateFilename, const char* password);
	unsigned char* generateGMACAuthTag(unsigned char* data, long data_len, const unsigned char* key);
	int deriveSymmetricKey(const char* filename, unsigned char* coord_x, unsigned char* coord_y, unsigned char** remainder_bytes);
	unsigned char* AESFancyOFB(const char* sym_key_filename, const char* plain_text, long plaintext_len);

	RSA* generateRSAKey(const char* RSAPublicFilename, const char* RSAPrivateFilename, int num_bits);

private:

	unsigned char* generatePBKDF2Key(long time_diff);
	long calculateTimeDifference();
	
};

