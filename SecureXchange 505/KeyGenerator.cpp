#include "KeyGenerator.h"
#include <openssl/applink.c>
#include "ASN1Structures.h"
#include <string.h>

void KeyGenerator::generateECKeyPair(const char* keyPublicFilename, const char* keyPrivateFilename, const char* password)
{
    EC_KEY* key = EC_KEY_new();

    int status;
    key = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (key == NULL) {
        fprintf(stderr, "Invalid curve name!\n");
        return;
    }

    status = EC_KEY_generate_key(key);
    if (status != 1) {
        fprintf(stderr, "Generation error!\n");
        return;
    }
    else {
        printf("Key pair generated successfully!\n");
    }

    FILE* privateFp = fopen(keyPrivateFilename, "w");
    FILE* publicFp = fopen(keyPublicFilename, "w");

    //salvam cheia privata criptata cu aes256cbc
    PEM_write_ECPrivateKey(privateFp, key, EVP_aes_256_cbc(), (unsigned char*)password, strlen(password), NULL, NULL);
    //salvam cheia publica in clar
    PEM_write_EC_PUBKEY(publicFp, key);
    fclose(privateFp);
    fclose(publicFp);

    //urmeaza sa generam GMACUL pentru cheia publica

    //aflam dimensiunea
    int pubkey_len = i2d_EC_PUBKEY(key, NULL);
    unsigned char* pubkey_buf = (unsigned char*)malloc(pubkey_len);

    //serializam cheia publica in array binar conf DER
    unsigned char* temp_ptr = pubkey_buf;
    if (i2d_EC_PUBKEY(key, &temp_ptr) != pubkey_len) {
        fprintf(stderr, "Eroare la serializarea cheii publice!\n");
        free(pubkey_buf);
        return;
    }

    long time_diff = calculateTimeDifference();
    unsigned char* pbkdf2_key = generatePBKDF2Key(time_diff);

    unsigned char* tag = generateGMACAuthTag(pubkey_buf, pubkey_len, pbkdf2_key);


    ASN1Structures::PubKeyMac* pubKeyMac = ASN1Structures::PubKeyMac_new();
    pubKeyMac->pubKeyName = ASN1_PRINTABLESTRING_new();
    pubKeyMac->macKey = ASN1_OCTET_STRING_new();
    pubKeyMac->macValue = ASN1_OCTET_STRING_new();

    ASN1_STRING_set(pubKeyMac->pubKeyName, keyPublicFilename, strlen(keyPublicFilename));
    ASN1_OCTET_STRING_set(pubKeyMac->macKey, pbkdf2_key, 32);
    ASN1_OCTET_STRING_set(pubKeyMac->macValue, tag, 16);

    //cream fisierul mac
    char macFilename[256];
    snprintf(macFilename, sizeof(macFilename), "%s.mac", keyPublicFilename);

    //salvam macul in file raw
    ASN1Structures::savePubKeyMacToFile(pubKeyMac, macFilename);

    ASN1Structures::PubKeyMac_free(pubKeyMac);
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
    target_tm.tm_year = (year < 70 ? 2000 + year : 1900 + year) - 1900;  // presupunem an YY < 70 înseamnă 2000+
    target_tm.tm_mon = month - 1;  // 0-based lunile
    target_tm.tm_mday = day;
    target_tm.tm_hour = hour;
    target_tm.tm_min = minute;
    target_tm.tm_sec = second;

    time_t target_time = _mkgmtime(&target_tm); //echivalentul timegm din linux
    if (target_time == -1) {
        fprintf(stderr, "Failed to convert target time.\n");
        return -1;
    }

    time_t now = time(nullptr);

    //long long diff = static_cast<long long>(target_time - now);
    long diff = (long)(now - target_time);

    static char result[32];
    snprintf(result, sizeof(result), "%lld", diff);

    printf("Time difference generat: %s\n", result);

    return diff;

}

unsigned char* KeyGenerator::generateGMACAuthTag(unsigned char* data, long data_len, const unsigned char* key)
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "CTX ERROR GENERATE");
        exit(-1);
    }
    const unsigned char iv[12] = { 0 };
    //generare in 2 pasi
    //init structura interna a cifrului
    EVP_EncryptInit(ctx, EVP_aes_128_gcm(), NULL, NULL);
    //actulizeaza cheia si iv-uls
    EVP_EncryptInit(ctx, NULL, key, iv);


    //criptare
    int len;
    EVP_EncryptUpdate(ctx, NULL, &len, data, data_len);

    EVP_EncryptFinal(ctx, NULL, &len);

    //save in tag
    int gmac_tag_len = 16; //aes-gcm 16bytes
    unsigned char* tag = (unsigned char*)malloc(gmac_tag_len);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, gmac_tag_len, tag);

    EVP_CIPHER_CTX_free(ctx);

    return tag;
}

unsigned char* KeyGenerator::generatePBKDF2Key(long time_diff)
{
    unsigned char* key = (unsigned char*)malloc(32 * sizeof(unsigned char));

    //convertire la cosnt unsigned char*  
    unsigned char time_buffer[8];
    for (int i = 0; i < 8; i++) {
        time_buffer[i] = (time_diff >> (i * 8)) & 0xFF;
    }

    //generam cheia (fara salt -> al 3-lea param NULL)
    //argm 4 = nr iteratii
    PKCS5_PBKDF2_HMAC((const char*)time_buffer, sizeof(long), NULL, 0, 10000, EVP_sha3_256(), 32, key);

    printf("Cheie PBKDF2 generata: ");
    for (int i = 0; i < 32; ++i) {
        printf("%02X", key[i]);
    }
    printf("\n");

    return key;
}


