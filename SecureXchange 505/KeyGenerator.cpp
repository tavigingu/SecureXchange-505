#include "KeyGenerator.h"
#include <openssl/applink.c>
#include <string.h>
#include "ASN1Structures.h"

void KeyGenerator::generateECKeyPair(const char* keyPublicFilename, const char* macFilename, const char* keyPrivateFilename, const char* password)
{
    if (!keyPublicFilename || !macFilename || !keyPrivateFilename || !password) {
        fprintf(stderr, "Invalid input parameters!\n");
        return;
    }

    EC_KEY* key = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!key) {
        fprintf(stderr, "Failed to create EC_KEY!\n");
        return;
    }

    int status = EC_KEY_generate_key(key);
    if (status != 1) {
        fprintf(stderr, "Generation error!\n");
        EC_KEY_free(key);
        return;
    }

    FILE* privateFp = fopen(keyPrivateFilename, "w");
    if (!privateFp) {
        fprintf(stderr, "Failed to open private key file!\n");
        EC_KEY_free(key);
        return;
    }

    FILE* publicFp = fopen(keyPublicFilename, "w");
    if (!publicFp) {
        fprintf(stderr, "Failed to open public key file!\n");
        fclose(privateFp);
        EC_KEY_free(key);
        return;
    }

    if (!PEM_write_ECPrivateKey(privateFp, key, EVP_aes_256_cbc(), (unsigned char*)password, strlen(password), NULL, NULL)) {
        fprintf(stderr, "Failed to write private key!\n");
        fclose(privateFp);
        fclose(publicFp);
        EC_KEY_free(key);
        return;
    }

    if (!PEM_write_EC_PUBKEY(publicFp, key)) {
        fprintf(stderr, "Failed to write public key!\n");
        fclose(privateFp);
        fclose(publicFp);
        EC_KEY_free(key);
        return;
    }
    fclose(privateFp);
    fclose(publicFp);

    int pubkey_len = i2d_EC_PUBKEY(key, NULL);
    if (pubkey_len <= 0) {
        fprintf(stderr, "Failed to get public key length!\n");
        EC_KEY_free(key);
        return;
    }

    unsigned char* pubkey_buf = (unsigned char*)malloc(pubkey_len);
    if (!pubkey_buf) {
        fprintf(stderr, "Memory allocation failed!\n");
        EC_KEY_free(key);
        return;
    }

    unsigned char* temp_ptr = pubkey_buf;
    if (i2d_EC_PUBKEY(key, &temp_ptr) != pubkey_len) {
        fprintf(stderr, "Eroare la serializarea cheii publice!\n");
        free(pubkey_buf);
        EC_KEY_free(key);
        return;
    }

    long time_diff = calculateTimeDifference();
    if (time_diff == -1) {
        fprintf(stderr, "Failed to calculate time difference!\n");
        free(pubkey_buf);
        EC_KEY_free(key);
        return;
    }

    unsigned char* pbkdf2_key = generatePBKDF2Key(time_diff);
    if (!pbkdf2_key) {
        fprintf(stderr, "Failed to generate PBKDF2 key!\n");
        free(pubkey_buf);
        EC_KEY_free(key);
        return;
    }

    unsigned char* tag = generateGMACAuthTag(pubkey_buf, pubkey_len, pbkdf2_key);
    if (!tag) {
        fprintf(stderr, "Failed to generate GMAC tag!\n");
        free(pubkey_buf);
        free(pbkdf2_key);
        EC_KEY_free(key);
        return;
    }

    PubKeyMac* pubKeyMac = PubKeyMac_new();
    if (!pubKeyMac) {
        fprintf(stderr, "Failed to create PubKeyMac!\n");
        free(pubkey_buf);
        free(pbkdf2_key);
        free(tag);
        EC_KEY_free(key);
        return;
    }

    pubKeyMac->pubKeyName = ASN1_PRINTABLESTRING_new();
    pubKeyMac->macKey = ASN1_OCTET_STRING_new();
    pubKeyMac->macValue = ASN1_OCTET_STRING_new();
    if (!pubKeyMac->pubKeyName || !pubKeyMac->macKey || !pubKeyMac->macValue) {
        fprintf(stderr, "Failed to allocate ASN1 structures!\n");
        PubKeyMac_free(pubKeyMac);
        free(pubkey_buf);
        free(pbkdf2_key);
        free(tag);
        EC_KEY_free(key);
        return;
    }

    if (!ASN1_STRING_set(pubKeyMac->pubKeyName, keyPublicFilename, strlen(keyPublicFilename)) ||
        !ASN1_OCTET_STRING_set(pubKeyMac->macKey, pbkdf2_key, 32) ||
        !ASN1_OCTET_STRING_set(pubKeyMac->macValue, tag, 16)) {
        fprintf(stderr, "Failed to set ASN1 values!\n");
        PubKeyMac_free(pubKeyMac);
        free(pubkey_buf);
        free(pbkdf2_key);
        free(tag);
        EC_KEY_free(key);
        return;
    }

    if (!ASN1Structures::savePubKeyMacToFile(pubKeyMac, macFilename)) {
        fprintf(stderr, "Failed to save PubKeyMac!\n");
        PubKeyMac_free(pubKeyMac);
        free(pubkey_buf);
        free(pbkdf2_key);
        free(tag);
        EC_KEY_free(key);
        return;
    }

    PubKeyMac_free(pubKeyMac);
    free(pubkey_buf);
    free(pbkdf2_key);
    free(tag);
    EC_KEY_free(key);
}

long KeyGenerator::calculateTimeDifference()
{
    const char* datetime_str = "050505050505Z";
    int year, month, day, hour, minute, second;

    if (sscanf(datetime_str, "%2d%2d%2d%2d%2d%2dZ", &year, &month, &day, &hour, &minute, &second) != 6) {
        fprintf(stderr, "Invalid date format!\n");
        return -1;
    }

    struct tm target_tm = { 0 };
    target_tm.tm_year = (year < 70 ? 2000 + year : 1900 + year) - 1900;
    target_tm.tm_mon = month - 1;
    target_tm.tm_mday = day;
    target_tm.tm_hour = hour;
    target_tm.tm_min = minute;
    target_tm.tm_sec = second;

    time_t target_time = _mkgmtime(&target_tm);
    if (target_time == -1) {
        fprintf(stderr, "Failed to convert target time.\n");
        return -1;
    }

    time_t now = time(nullptr);
    if (now == -1) {
        fprintf(stderr, "Failed to get current time!\n");
        return -1;
    }

    long diff = (long)(now - target_time);
    return diff;
}

unsigned char* KeyGenerator::generateGMACAuthTag(unsigned char* data, long data_len, const unsigned char* key)
{
    if (!data || data_len <= 0 || !key) {
        fprintf(stderr, "Invalid input parameters!\n");
        return nullptr;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "CTX ERROR GENERATE!\n");
        return nullptr;
    }

    const unsigned char iv[12] = { 0 };
    if (!EVP_EncryptInit(ctx, EVP_aes_128_gcm(), NULL, NULL) ||
        !EVP_EncryptInit(ctx, NULL, key, iv)) {
        fprintf(stderr, "Failed to initialize GMAC!\n");
        EVP_CIPHER_CTX_free(ctx);
        return nullptr;
    }

    int len;
    if (!EVP_EncryptUpdate(ctx, NULL, &len, data, data_len) ||
        !EVP_EncryptFinal(ctx, NULL, &len)) {
        fprintf(stderr, "Failed to compute GMAC!\n");
        EVP_CIPHER_CTX_free(ctx);
        return nullptr;
    }

    int gmac_tag_len = 16;
    unsigned char* tag = (unsigned char*)malloc(gmac_tag_len);
    if (!tag) {
        fprintf(stderr, "Memory allocation failed!\n");
        EVP_CIPHER_CTX_free(ctx);
        return nullptr;
    }

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, gmac_tag_len, tag)) {
        fprintf(stderr, "Failed to retrieve GMAC tag!\n");
        free(tag);
        EVP_CIPHER_CTX_free(ctx);
        return nullptr;
    }

    EVP_CIPHER_CTX_free(ctx);
    return tag;
}

int KeyGenerator::deriveSymmetricKey(const char* filename, unsigned char* coord_x, unsigned char* coord_y, unsigned char** remainder_bytes)
{
    if (!coord_x || !coord_y || !remainder_bytes || !*remainder_bytes) {
        fprintf(stderr, "Eroare: coord_x, coord_y sau remainder_bytes este nullptr\n");
        return -1;
    }

    unsigned char* sym_key = (unsigned char*)malloc(16 * sizeof(unsigned char));
    if (!sym_key) {
        fprintf(stderr, "Eroare: Nu s-a putut aloca memoria pentru sym_key\n");
        return -1;
    }

    unsigned char x_SHA256[32];
    if (!SHA256(coord_x, 32, x_SHA256)) {
        fprintf(stderr, "Eroare: SHA256 a eșuat\n");
        free(sym_key);
        return -1;
    }

    unsigned char sym_left[16];
    for (int i = 0; i < 16; i++) {
        sym_left[i] = x_SHA256[i] ^ x_SHA256[i + 16];
    }

    unsigned char sym_right[48];
    if (PKCS5_PBKDF2_HMAC((const char*)coord_y, 32, NULL, 0, 1000, EVP_sha384(), 48, sym_right) != 1) {
        fprintf(stderr, "Eroare: PKCS5_PBKDF2_HMAC a eșuat\n");
        free(sym_key);
        return -1;
    }

    for (int i = 0; i < 16; i++) {
        sym_key[i] = sym_left[i] ^ sym_right[i];
    }

    memcpy(*remainder_bytes, sym_right + 16, 32);

    SymElements* symElements = SymElements_new();
    if (!symElements) {
        fprintf(stderr, "Eroare: SymElements_new a eșuat\n");
        free(sym_key);
        return -1;
    }

    int sym_id = IDGenerator::generate();
    if (!ASN1_INTEGER_set(symElements->symElementsID, sym_id)) {
        fprintf(stderr, "Eroare: ASN1_INTEGER_set a eșuat pentru symElementsID\n");
        SymElements_free(symElements);
        free(sym_key);
        return -1;
    }

    if (!ASN1_OCTET_STRING_set(symElements->symKey, sym_key, 16)) {
        fprintf(stderr, "Eroare: ASN1_OCTET_STRING_set a eșuat pentru symKey\n");
        SymElements_free(symElements);
        free(sym_key);
        return -1;
    }

    if (!ASN1_OCTET_STRING_set(symElements->iv, sym_right + 16, 16)) {
        fprintf(stderr, "Eroare: ASN1_OCTET_STRING_set a eșuat pentru iv\n");
        SymElements_free(symElements);
        free(sym_key);
        return -1;
    }


    if (!ASN1Structures::saveSymElementsToFile(symElements, filename)) {
        fprintf(stderr, "Eroare: Nu s-a putut salva SymElements în fișier\n");
        SymElements_free(symElements);
        free(sym_key);
        return -1;
    }

    SymElements_free(symElements);
    free(sym_key);
    printf("---> Cheie simetrica derivata cu succes!\n");
    return sym_id;
}


unsigned char* KeyGenerator::AESFancyOFB(const char* sym_key_filename, const char* plain_text, long plaintext_len)
{
    if (!sym_key_filename || !plain_text || plaintext_len <= 0) {
        fprintf(stderr, "Invalid input parameters!\n");
        return nullptr;
    }

    SymElements* symElements = ASN1Structures::loadSymElementsFromFile(sym_key_filename);
    if (!symElements) {
        fprintf(stderr, "Failed to load SymElements!\n");
        return nullptr;
    }

    const unsigned char* IV_const = ASN1_STRING_get0_data(symElements->iv);
    const unsigned char* symKey = ASN1_STRING_get0_data(symElements->symKey);
    long symId = ASN1_INTEGER_get(symElements->symElementsID);
    if (!IV_const || !symKey) {
        fprintf(stderr, "Invalid SymElements data!\n");
        SymElements_free(symElements);
        return nullptr;
    }

    unsigned char* ciphertext = (unsigned char*)OPENSSL_malloc(plaintext_len);
    if (!ciphertext) {
        fprintf(stderr, "Memory allocation failed!\n");
        SymElements_free(symElements);
        return nullptr;
    }

    unsigned char iv[16];
    memcpy(iv, IV_const, 16); // Copiază IV într-un buffer modificabil
    unsigned char inv_iv[16];
    for (int i = 0; i < 16; i++) {
        inv_iv[i] = iv[15 - i];
    }

    int out_len;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        fprintf(stderr, "Eroare la crearea contextului pentru aes\n");
        OPENSSL_free(ciphertext);
        SymElements_free(symElements);
        return nullptr;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, symKey, NULL) != 1) {
        fprintf(stderr, "Failed to initialize AES!\n");
        EVP_CIPHER_CTX_free(ctx);
        OPENSSL_free(ciphertext);
        SymElements_free(symElements);
        return nullptr;
    }

    for (int i = 0; i < plaintext_len; i += 16) {
        unsigned char keystream[16];
        int len = (plaintext_len - i < 16) ? (plaintext_len - i) : 16;
        if (EVP_EncryptUpdate(ctx, keystream, &out_len, iv, 16) != 1) {
            fprintf(stderr, "AES encryption failed!\n");
            EVP_CIPHER_CTX_free(ctx);
            OPENSSL_free(ciphertext);
            SymElements_free(symElements);
            return nullptr;
        }
        memcpy(iv, keystream, 16); 

        for (int j = 0; j < 16; j++) keystream[j] ^= inv_iv[j];

        for (int j = 0; j < len; j++) {
            ciphertext[i + j] = ((unsigned char*)plain_text)[i + j] ^ keystream[j];
        }
    }

  /*  printf("CIPHER: \n");
    for (int i = 0; i < plaintext_len; i++) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");*/

    EVP_CIPHER_CTX_free(ctx);
    SymElements_free(symElements);

    printf("---> Encrypted data cu AES FANCY OFB\n");
    return ciphertext;
}

RSA* KeyGenerator::generateRSAKey(const char* RSAPublicFilename, const char* RSAPrivateFilename, int num_bits)
{
    if (!RSAPublicFilename || !RSAPrivateFilename || num_bits < 2048) {
        fprintf(stderr, "Invalid number of bits for generating rsa key pair\n");
        return nullptr;
    }

    BIGNUM* exponent = BN_new();
    if (!exponent) {
        fprintf(stderr, "Failed to create BIGNUM!\n");
        return nullptr;
    }

    if (!BN_set_word(exponent, RSA_F4)) {
        fprintf(stderr, "Failed to set exponent!\n");
        BN_free(exponent);
        return nullptr;
    }

    RSA* rsa = RSA_new();
    if (!rsa) {
        fprintf(stderr, "Failed to create RSA!\n");
        BN_free(exponent);
        return nullptr;
    }

    if (RSA_generate_key_ex(rsa, num_bits, exponent, nullptr) != 1) {
        fprintf(stderr, "Error generating rsa key pair\n");
        BN_free(exponent);
        RSA_free(rsa);
        return nullptr;
    }

    FILE* privateFp = fopen(RSAPrivateFilename, "w");
    if (!privateFp) {
        fprintf(stderr, "Failed to open private key file!\n");
        BN_free(exponent);
        RSA_free(rsa);
        return nullptr;
    }

    FILE* publicFp = fopen(RSAPublicFilename, "w");
    if (!publicFp) {
        fprintf(stderr, "Failed to open public key file!\n");
        fclose(privateFp);
        BN_free(exponent);
        RSA_free(rsa);
        return nullptr;
    }

    if (!PEM_write_RSAPrivateKey(privateFp, rsa, NULL, NULL, NULL, NULL, NULL)) {
        fprintf(stderr, "Failed to write private key!\n");
        fclose(privateFp);
        fclose(publicFp);
        BN_free(exponent);
        RSA_free(rsa);
        return nullptr;
    }

    if (!PEM_write_RSA_PUBKEY(publicFp, rsa)) {
        fprintf(stderr, "Failed to write public key!\n");
        fclose(privateFp);
        fclose(publicFp);
        BN_free(exponent);
        RSA_free(rsa);
        return nullptr;
    }

    fclose(privateFp);
    fclose(publicFp);
    BN_free(exponent);
    return rsa;
}

unsigned char* KeyGenerator::generatePBKDF2Key(long time_diff)
{
    unsigned char* key = (unsigned char*)malloc(32 * sizeof(unsigned char));
    if (!key) {
        fprintf(stderr, "Memory allocation failed!\n");
        return nullptr;
    }

    unsigned char time_buffer[8];
    for (int i = 0; i < 8; i++) {
        time_buffer[i] = (time_diff >> (i * 8)) & 0xFF;
    }

    if (PKCS5_PBKDF2_HMAC((const char*)time_buffer, sizeof(long), NULL, 0, 10000, EVP_sha3_256(), 32, key) != 1) {
        fprintf(stderr, "Failed to generate PBKDF2 key!\n");
        free(key);
        return nullptr;
    }

    return key;
}