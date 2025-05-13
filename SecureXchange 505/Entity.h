#pragma once
#include <string.h>
#include "KeyGenerator.h"
#include "Logger.h"

class Entity
{
public:
	
	Entity(int id, const char* name);
	~Entity();

	void generateKeys(const char* password);
	bool validatePublicKey(const char* publicKeyFile, const char* macFile);
	bool ECDHKeyExchange(Entity& partner, unsigned char** coordX, unsigned char** coordY);
	int deriveSymmetricKey(const char* filename, unsigned char* coord_x, unsigned char* coord_y, unsigned char** remainder_bytes);
	bool signData(const unsigned char* data, size_t data_len, unsigned char** signature, size_t* signature_len);
	unsigned char* encryptData(const char* sym_key_filename, const char* plain_text, long plaintext_len);

	EC_KEY* loadPrivateKey();
	EC_KEY* loadPublicKey();
	RSA* loadPrivateRSAKey();

	int getID() const;
	const char* getName() const;
	const char* getPrivateKeyFile() const;
	const char* getPublicKeyFile() const;
	const char* getMacFile() const;


private:
	int ID;
	char* name;
	char* private_key_file;
	char* password;
	char* public_key_file;
	char* mac_file;
	char* private_rsa_file;
	char* public_rsa_file;
	KeyGenerator key_generator;


	
};
