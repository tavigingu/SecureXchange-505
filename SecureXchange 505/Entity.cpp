#include "Entity.h"
#include "ASN1Structures.h"


Entity::Entity(int id, const char* name)
{
    this->ID = id;
    this->name =strdup(name);

    char privFile[256], pubFile[256], macFile[256], rsaPrivFile[256], rsaPubFile[256];
    snprintf(privFile, sizeof(privFile), "%s_private.pem", name);
    snprintf(pubFile, sizeof(pubFile), "%s_public.pem", name);
    snprintf(macFile, sizeof(macFile), "%s.mac", name);
    snprintf(rsaPrivFile, sizeof(rsaPrivFile), "%s_rsa_priv.pem", name);
    snprintf(rsaPubFile, sizeof(rsaPubFile), "%s_rsa_pub.pem", name);

    this->private_key_file = strdup(privFile);
    this->public_key_file = strdup(pubFile);
    this->mac_file = strdup(macFile);
    this->private_rsa_file = strdup(rsaPrivFile);
    this->public_rsa_file = strdup(rsaPubFile);
    this->password = NULL;

    Logger::getInstance().logAction(this->name, "Inregistrare in sistem");

    printf("---> Instanta %s cu id-ul %d a fost creata!\n", name, ID);

    key_generator.generateRSAKey(public_rsa_file, private_rsa_file, 3072);

    Logger::getInstance().logAction(this->name, "Generare chei RSA");

    printf("---> Perehce de chei RSA generata cu succes pentru %s cu id-ul %d!\n", name, ID);

}

Entity::~Entity()
{
    if (name)
        free(name);
    if (private_key_file)
        free(private_key_file);
    if (public_key_file)
        free(public_key_file);
    if (mac_file)
        free(mac_file);
    if (password)
        free(password);
    if (public_rsa_file)
        free(public_rsa_file);
    if (private_rsa_file)
        free(private_rsa_file);
}

void Entity::generateKeys(const char* password)
{   
    if (this->password)
        free(this->password);
    this->password = strdup(password);

    key_generator.generateECKeyPair(public_key_file, mac_file, private_key_file, password);

    Logger::getInstance().logAction(this->name, "Generare chei ECC");
    printf("---> Pereche chei EC generate cu success pentru %s cu id-ul %d!\n", this->name, ID);
}

bool Entity::validatePublicKey(const char* publicKeyFile, const char* macFile)
{
    //incarca structura .mac a cheii publice
    PubKeyMac* pubKeyMac = ASN1Structures::loadPubKeyMacFromFile(macFile);
    
    //incarca cheia publica
    FILE* fp = fopen(publicKeyFile, "r");
    if (!fp) {
        fprintf(stderr, "Cannot open public key file %s\n", publicKeyFile);
        PubKeyMac_free(pubKeyMac);
        return false;
    }

    EVP_PKEY* pubKey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!pubKey) {
        fprintf(stderr, "Failed to read public key from %s\n", publicKeyFile);
        PubKeyMac_free(pubKeyMac);
        return false;
    }

    //serializam cheia public in der
    int pubkey_len = i2d_PUBKEY(pubKey, NULL);
    unsigned char* pubkey_buf = (unsigned char*)malloc(pubkey_len);
    unsigned char* temp_ptr = pubkey_buf;

    if (i2d_PUBKEY(pubKey, &temp_ptr) != pubkey_len) {
        fprintf(stderr, "Error serializing public key\n");
        free(pubkey_buf);
        EVP_PKEY_free(pubKey);
        PubKeyMac_free(pubKeyMac);
        return false;
    }

    unsigned char* regenerated_tag = key_generator.generateGMACAuthTag(pubkey_buf, pubkey_len, pubKeyMac->macKey->data);
    if (!regenerated_tag) {
        fprintf(stderr, "Failed to regenerate GMAC tag\n");
        free(pubkey_buf);
        EVP_PKEY_free(pubKey);
        PubKeyMac_free(pubKeyMac);
        return false;
    }

    bool same_tag = (pubKeyMac->macValue->length == 16) &&
        (memcmp(pubKeyMac->macValue->data, regenerated_tag, 16) == 0);

    free(pubkey_buf);
    free(regenerated_tag);
    EVP_PKEY_free(pubKey);
    PubKeyMac_free(pubKeyMac);

    if (same_tag)
        printf("---> Entitatea %s a validat cu succes cheia entitati partener!\n", name);
    else
        printf("---> Entitatea %s nu a validat cu succes cheia entitati partener!\n", name);

    Logger::getInstance().logAction(this->name, "Validare cheie partener");
    
    return same_tag;
}

bool Entity::ECDHKeyExchange(Entity& partner, unsigned char** coord_x, unsigned char** coord_y)
{
    
    EC_KEY* my_ec_priv = loadPrivateKey();
    if (!my_ec_priv) {
        fprintf(stderr, "Failed to load private key\n");
        return false;
    }

    EC_KEY* partner_ec_public = partner.loadPublicKey();
    if (!partner_ec_public) {
        fprintf(stderr, "Failed to load partner's public key\n");
        EC_KEY_free(my_ec_priv);
        return false;
    }

    const EC_GROUP* curve = EC_KEY_get0_group(my_ec_priv);
    const EC_POINT* pubPoint = EC_KEY_get0_public_key(partner_ec_public);

    EC_POINT* sharedPoint = EC_POINT_new(curve);
    if (!sharedPoint) {
        fprintf(stderr, "Failed to create shared point\n");
        EC_KEY_free(my_ec_priv);
        EC_KEY_free(partner_ec_public);
        return false;
    }

    if (!EC_POINT_mul(curve, sharedPoint, NULL, pubPoint, EC_KEY_get0_private_key(my_ec_priv), NULL)) {
        fprintf(stderr, "ECDH computation failed\n");
        EC_POINT_free(sharedPoint);
        EC_KEY_free(my_ec_priv);
        EC_KEY_free(partner_ec_public);
        return false;
    }

    BIGNUM* xNumber = BN_new();
    BIGNUM* yNumber = BN_new();
    if (!xNumber || !yNumber) {
        fprintf(stderr, "Failed to allocate BIGNUMs\n");
        BN_free(xNumber);
        BN_free(yNumber);
        EC_POINT_free(sharedPoint);
        EC_KEY_free(my_ec_priv);
        EC_KEY_free(partner_ec_public);
        return false;
    }

    if (!EC_POINT_get_affine_coordinates_GFp(curve, sharedPoint, xNumber, yNumber, NULL)) {
        fprintf(stderr, "Failed to get affine coordinates\n");
        BN_free(xNumber);
        BN_free(yNumber);
        EC_POINT_free(sharedPoint);
        EC_KEY_free(my_ec_priv);
        EC_KEY_free(partner_ec_public);
        return false;
    }

    BN_bn2binpad(xNumber, *coord_x, 32);
    BN_bn2binpad(yNumber, *coord_y, 32);

    BN_free(xNumber);
    BN_free(yNumber);
    EC_POINT_free(sharedPoint);
    EC_KEY_free(my_ec_priv);
    EC_KEY_free(partner_ec_public);

    printf("---> Schimb ECDH intre %s si %s efectuat cu succes!\n", name, partner.getName());
    Logger::getInstance().logAction(this->name, "Efectuarea schimbului ECDH");
    Logger::getInstance().logAction(partner.getName(), "Efectuarea schimbului ECDH");

    return true;
}

int Entity::deriveSymmetricKey(const char* filename, unsigned char* coord_x, unsigned char* coord_y, unsigned char** remainder_bytes)
{
    Logger::getInstance().logAction(this->name, "Derivarea cheii simetrice");
    return key_generator.deriveSymmetricKey(filename, coord_x, coord_y, remainder_bytes);
}

bool Entity::signData(const unsigned char* data, size_t data_len, unsigned char** signature, size_t* signature_len)
{
    RSA* rsa_key = loadPrivateRSAKey();
    if (!rsa_key) {
        fprintf(stderr, "Failed to load RSA private key\n");
        return false;
    }

    // Create SHA-256 hash of the input data
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(data, data_len, hash);

    // Allocate memory for the signature (RSA signature size depends on key size)
    *signature_len = RSA_size(rsa_key);
    *signature = (unsigned char*)malloc(*signature_len);
    if (!*signature) {
        fprintf(stderr, "Failed to allocate memory for signature\n");
        RSA_free(rsa_key);
        return false;
    }

    // Sign the hash using RSA private key with PKCS#1 padding
    unsigned int sig_len = 0;
    int ret = RSA_sign(NID_sha256, hash, SHA256_DIGEST_LENGTH, *signature, &sig_len, rsa_key);
    if (ret != 1) {
        fprintf(stderr, "Failed to sign data\n");
        free(*signature);
        *signature = NULL;
        RSA_free(rsa_key);
        return false;
    }

    *signature_len = sig_len;
    RSA_free(rsa_key);

    Logger::getInstance().logAction(this->name, "Semnarea datelor");
    return true;
}

unsigned char* Entity::encryptData(const char* sym_key_filename, const char* plain_text, long plaintext_len)
{
    Logger::getInstance().logAction(this->name, "Criptarea datelor folosind AES Fancy OFB");
    return key_generator.AESFancyOFB(sym_key_filename, plain_text, plaintext_len);
}


EC_KEY* Entity::loadPublicKey() {

    FILE* fp = fopen(public_key_file, "r");
    if (!fp) {
        fprintf(stderr, "Cannot open public key file %s\n", public_key_file);
        return NULL;
    }

    //citeste cheia ca EVP_PKEY
    EVP_PKEY* pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);

    if (!pkey) {
        fprintf(stderr, "Failed to read public key from %s\n", public_key_file);
        return NULL;
    }

    // extrage EC_KEY din EVP_PKEY
    EC_KEY* eckey = EVP_PKEY_get1_EC_KEY(pkey);
    EVP_PKEY_free(pkey);

    if (!eckey) {
        fprintf(stderr, "Failed to extract EC_KEY from public key\n");
        return NULL;
    }

    return eckey;
}

RSA* Entity::loadPrivateRSAKey()
{
    
    FILE* fp = fopen(private_rsa_file, "r");
    if (!fp) {
        fprintf(stderr, "Cannot open private RSA key file %s\n", private_rsa_file);
        return NULL;
    }

    RSA* rsa = PEM_read_RSAPrivateKey(fp, NULL, NULL, (void*)password);
    fclose(fp);

    if (!rsa) {
        fprintf(stderr, "Failed to read RSA private key from %s\n", private_rsa_file);
        return NULL;
    }

    return rsa;
   
}

int Entity::getID() const {
    return ID;
}

const char* Entity::getName() const {
    return name;
}

const char* Entity::getPrivateKeyFile() const {
    return private_key_file;
}

const char* Entity::getPublicKeyFile() const {
    return public_key_file;
}

const char* Entity::getMacFile() const {
    return mac_file;
}

EC_KEY* Entity::loadPrivateKey()
{
    FILE* fp = fopen(private_key_file, "r");
    if (!fp) {
        fprintf(stderr, "Cannot open private key file %s\n", private_key_file);
        return NULL;
    }

    EC_KEY* eckey = PEM_read_ECPrivateKey(fp, NULL, NULL, (void*)password);
    fclose(fp);

    if (!eckey) {
        fprintf(stderr, "Failed to read private key from %s\n", private_key_file);
        return NULL;
    }

    return eckey;
}
