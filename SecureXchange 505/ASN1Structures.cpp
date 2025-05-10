#define _CRT_SECURE_NO_WARNINGS
#include "ASN1Structures.h"



int serializePubKeyMacToDER(const PubKeyMac* pubKeyMac, unsigned char** der_buf, int* der_len) {
    if (!pubKeyMac || !der_buf || !der_len) {
        fprintf(stderr, "Invalid parameters for serializePubKeyMacToDER\n");
        return 0;
    }

    // Calculăm lungimea buffer-ului DER
    *der_len = i2d_PubKeyMac(pubKeyMac, NULL);
    if (*der_len <= 0) {
        fprintf(stderr, "Error calculating DER length: %s\n", ERR_error_string(ERR_get_error(), NULL));
        return 0;
    }

    // Alocăm buffer-ul
    *der_buf = (unsigned char*)malloc(*der_len);
    if (!*der_buf) {
        fprintf(stderr, "Memory allocation failed for DER buffer\n");
        return 0;
    }

    // Serializăm în DER
    unsigned char* temp_ptr = *der_buf;
    if (i2d_PubKeyMac(pubKeyMac, &temp_ptr) != *der_len) {
        fprintf(stderr, "Error serializing PubKeyMac to DER: %s\n", ERR_error_string(ERR_get_error(), NULL));
        free(*der_buf);
        *der_buf = NULL;
        return 0;
    }

    return 1;
}

PubKeyMac* deserializePubKeyMacFromDER(const unsigned char* der_buf, int der_len) {
    if (!der_buf || der_len <= 0) {
        fprintf(stderr, "Invalid parameters for deserializePubKeyMacFromDER\n");
        return NULL;
    }

    // Deserializăm buffer-ul DER într-o structură PubKeyMac
    const unsigned char* temp_ptr = der_buf;
    PubKeyMac* pubKeyMac = d2i_PubKeyMac(NULL, &temp_ptr, der_len);
    if (!pubKeyMac) {
        fprintf(stderr, "Error deserializing PubKeyMac from DER: %s\n", ERR_error_string(ERR_get_error(), NULL));
        return NULL;
    }

    return pubKeyMac;
}

int savePubKeyMacToFile(const PubKeyMac* pubKeyMac, const char* filename) {
    if (!pubKeyMac || !filename) {
        fprintf(stderr, "Invalid parameters for savePubKeyMacToFile\n");
        return 0;
    }

    // Serializăm PubKeyMac în DER
    unsigned char* der_buf = NULL;
    int der_len = 0;
    if (!serializePubKeyMacToDER(pubKeyMac, &der_buf, &der_len)) {
        return 0;
    }

    // Deschidem fișierul pentru scriere
    FILE* fp = fopen(filename, "wb");
    if (!fp) {
        fprintf(stderr, "Cannot open file %s for writing\n", filename);
        free(der_buf);
        return 0;
    }

    // Scriem buffer-ul DER în fișier
    if (fwrite(der_buf, 1, der_len, fp) != der_len) {
        fprintf(stderr, "Error writing to file %s\n", filename);
        fclose(fp);
        free(der_buf);
        return 0;
    }

    fclose(fp);
    free(der_buf);
    return 1;
}

PubKeyMac* loadPubKeyMacFromFile(const char* filename) {
    if (!filename) {
        fprintf(stderr, "Invalid filename for loadPubKeyMacFromFile\n");
        return NULL;
    }

    // Deschidem fișierul pentru citire
    FILE* fp = fopen(filename, "rb");
    if (!fp) {
        fprintf(stderr, "Cannot open file %s for reading\n", filename);
        return NULL;
    }

    // Determinăm dimensiunea fișierului
    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (file_size <= 0) {
        fprintf(stderr, "Invalid file size for %s\n", filename);
        fclose(fp);
        return NULL;
    }

    // Alocăm buffer-ul pentru conținutul fișierului
    unsigned char* der_buf = (unsigned char*)malloc(file_size);
    if (!der_buf) {
        fprintf(stderr, "Memory allocation failed for file buffer\n");
        fclose(fp);
        return NULL;
    }

    // Citim conținutul fișierului
    if (fread(der_buf, 1, file_size, fp) != file_size) {
        fprintf(stderr, "Error reading file %s\n", filename);
        free(der_buf);
        fclose(fp);
        return NULL;
    }
    fclose(fp);

    // Deserializăm buffer-ul DER
    PubKeyMac* pubKeyMac = deserializePubKeyMacFromDER(der_buf, file_size);
    free(der_buf);

    if (!pubKeyMac) {
        fprintf(stderr, "Failed to deserialize PubKeyMac from file %s\n", filename);
        return NULL;
    }

    return pubKeyMac;
}
