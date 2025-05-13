#define _CRT_SECURE_NO_WARNINGS
#include "ASN1Structures.h"
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/bio.h>

ASN1_SEQUENCE(PubKeyMac) = {
     ASN1_SIMPLE(PubKeyMac, pubKeyName, ASN1_PRINTABLESTRING),
     ASN1_SIMPLE(PubKeyMac, macKey, ASN1_OCTET_STRING),
     ASN1_SIMPLE(PubKeyMac, macValue, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(PubKeyMac);

IMPLEMENT_ASN1_FUNCTIONS(PubKeyMac);

ASN1_SEQUENCE(SymElements) = {
    ASN1_SIMPLE(SymElements, symElementsID, ASN1_INTEGER),
    ASN1_SIMPLE(SymElements, symKey, ASN1_OCTET_STRING),
    ASN1_SIMPLE(SymElements, iv, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(SymElements)

IMPLEMENT_ASN1_FUNCTIONS(SymElements)

ASN1_SEQUENCE(Transaction) = {
    ASN1_SIMPLE(Transaction, transactionID, ASN1_INTEGER),
    ASN1_SIMPLE(Transaction, subject, ASN1_PRINTABLESTRING),
    ASN1_SIMPLE(Transaction, senderID, ASN1_INTEGER),
    ASN1_SIMPLE(Transaction, receiverID, ASN1_INTEGER),
    ASN1_SIMPLE(Transaction, symElementsID, ASN1_INTEGER),
    ASN1_SIMPLE(Transaction, encryptedData, ASN1_OCTET_STRING),
    ASN1_SIMPLE(Transaction, transactionSign, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(Transaction)

IMPLEMENT_ASN1_FUNCTIONS(Transaction)

namespace ASN1Structures {
   
    int serializePubKeyMacToDER(const PubKeyMac* pubKeyMac, unsigned char** der_buf, int* der_len) {
        if (!pubKeyMac || !der_buf || !der_len) {
            fprintf(stderr, "Invalid parameters for serializePubKeyMacToDER\n");
            return 0;
        }

        *der_len = i2d_PubKeyMac(pubKeyMac, NULL);
        if (*der_len <= 0) {
            fprintf(stderr, "Error calculating DER length: %s\n", ERR_error_string(ERR_get_error(), NULL));
            return 0;
        }

        *der_buf = (unsigned char*)malloc(*der_len);
        if (!*der_buf) {
            fprintf(stderr, "Memory allocation failed for DER buffer\n");
            return 0;
        }

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

        unsigned char* der_buf = NULL;
        int der_len = 0;
        if (!serializePubKeyMacToDER(pubKeyMac, &der_buf, &der_len)) {
            return 0;
        }

        FILE* fp = fopen(filename, "wb");
        if (!fp) {
            fprintf(stderr, "Cannot open file %s for writing\n", filename);
            free(der_buf);
            return 0;
        }

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

        FILE* fp = fopen(filename, "rb");
        if (!fp) {
            fprintf(stderr, "Cannot open file %s for reading\n", filename);
            return NULL;
        }

        fseek(fp, 0, SEEK_END);
        long file_size = ftell(fp);
        fseek(fp, 0, SEEK_SET);

        if (file_size <= 0) {
            fprintf(stderr, "Invalid file size for %s\n", filename);
            fclose(fp);
            return NULL;
        }

        unsigned char* der_buf = (unsigned char*)malloc(file_size);
        if (!der_buf) {
            fprintf(stderr, "Memory allocation failed for file buffer\n");
            fclose(fp);
            return NULL;
        }

        if (fread(der_buf, 1, file_size, fp) != file_size) {
            fprintf(stderr, "Error reading file %s\n", filename);
            free(der_buf);
            fclose(fp);
            return NULL;
        }
        fclose(fp);

        PubKeyMac* pubKeyMac = deserializePubKeyMacFromDER(der_buf, file_size);
        free(der_buf);

        if (!pubKeyMac) {
            fprintf(stderr, "Failed to deserialize PubKeyMac from file %s\n", filename);
            return NULL;
        }

        return pubKeyMac;
    }

    int serializeSymElementsToDER(const SymElements* symElements, unsigned char** der_buf, int* der_len) {
        if (!symElements || !der_buf || !der_len) {
            fprintf(stderr, "Invalid parameters for serializeSymElementsToDER\n");
            return 0;
        }

        *der_len = i2d_SymElements(symElements, NULL);
        if (*der_len <= 0) {
            fprintf(stderr, "Error calculating DER length: %s\n", ERR_error_string(ERR_get_error(), NULL));
            return 0;
        }

        *der_buf = (unsigned char*)malloc(*der_len);
        if (!*der_buf) {
            fprintf(stderr, "Memory allocation failed for DER buffer\n");
            return 0;
        }

        unsigned char* temp_ptr = *der_buf;
        if (i2d_SymElements(symElements, &temp_ptr) != *der_len) {
            fprintf(stderr, "Error serializing SymElements to DER: %s\n", ERR_error_string(ERR_get_error(), NULL));
            free(*der_buf);
            *der_buf = NULL;
            return 0;
        }

        return 1;
    }

    SymElements* deserializeSymElementsFromDER(const unsigned char* der_buf, int der_len) {
        if (!der_buf || der_len <= 0) {
            fprintf(stderr, "Invalid parameters for deserializeSymElementsFromDER\n");
            return NULL;
        }

        const unsigned char* temp_ptr = der_buf;
        SymElements* symElements = d2i_SymElements(NULL, &temp_ptr, der_len);
        if (!symElements) {
            fprintf(stderr, "Error deserializing SymElements from DER: %s\n", ERR_error_string(ERR_get_error(), NULL));
            return NULL;
        }

        return symElements;
    }

    int saveSymElementsToFile(const SymElements* symElements, const char* filename) {
        if (!symElements || !filename) {
            fprintf(stderr, "Invalid parameters for saveSymElementsToFile\n");
            return 0;
        }

        unsigned char* der_buf = NULL;
        int der_len = 0;
        if (!serializeSymElementsToDER(symElements, &der_buf, &der_len)) {
            return 0;
        }


        FILE* fp = fopen(filename, "wb");
        if (!fp) {
            fprintf(stderr, "Cannot open file %s for writing\n", filename);
            free(der_buf);
            return 0;
        }

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

    SymElements* loadSymElementsFromFile(const char* filename) {
        if (!filename) {
            fprintf(stderr, "Invalid filename for loadSymElementsFromFile\n");
            return NULL;
        }

        FILE* fp = fopen(filename, "rb");
        if (!fp) {
            fprintf(stderr, "Cannot open file %s for reading\n", filename);
            return NULL;
        }

        fseek(fp, 0, SEEK_END);
        long file_size = ftell(fp);
        fseek(fp, 0, SEEK_SET);

        if (file_size <= 0) {
            fprintf(stderr, "Invalid file size for %s\n", filename);
            fclose(fp);
            return NULL;
        }

        unsigned char* der_buf = (unsigned char*)malloc(file_size);
        if (!der_buf) {
            fprintf(stderr, "Memory allocation failed for file buffer\n");
            fclose(fp);
            return NULL;
        }

        if (fread(der_buf, 1, file_size, fp) != file_size) {
            fprintf(stderr, "Error reading file %s\n", filename);
            free(der_buf);
            fclose(fp);
            return NULL;
        }
        fclose(fp);

        SymElements* symElements = deserializeSymElementsFromDER(der_buf, file_size);
        free(der_buf);

        if (!symElements) {
            fprintf(stderr, "Failed to deserialize SymElements from file %s\n", filename);
            return NULL;
        }

        return symElements;
    }

    int serializeTransactionToDER(const Transaction* transaction, unsigned char** der_buf, int* der_len) {
        if (!transaction || !der_buf || !der_len) {
            fprintf(stderr, "Invalid parameters for serializeTransactionToDER\n");
            return 0;
        }

        *der_len = i2d_Transaction(transaction, NULL);
        if (*der_len <= 0) {
            fprintf(stderr, "Error calculating DER length: %s\n", ERR_error_string(ERR_get_error(), NULL));
            return 0;
        }

        *der_buf = (unsigned char*)malloc(*der_len);
        if (!*der_buf) {
            fprintf(stderr, "Memory allocation failed for DER buffer\n");
            return 0;
        }

        unsigned char* temp_ptr = *der_buf;
        if (i2d_Transaction(transaction, &temp_ptr) != *der_len) {
            fprintf(stderr, "Error serializing Transaction to DER: %s\n", ERR_error_string(ERR_get_error(), NULL));
            free(*der_buf);
            *der_buf = NULL;
            return 0;
        }

        return 1;
    }

    Transaction* deserializeTransactionFromDER(const unsigned char* der_buf, int der_len) {
        if (!der_buf || der_len <= 0) {
            fprintf(stderr, "Invalid parameters for deserializeTransactionFromDER\n");
            return NULL;
        }

        const unsigned char* temp_ptr = der_buf;
        Transaction* transaction = d2i_Transaction(NULL, &temp_ptr, der_len);
        if (!transaction) {
            fprintf(stderr, "Error deserializing Transaction from DER: %s\n", ERR_error_string(ERR_get_error(), NULL));
            return NULL;
        }

        return transaction;
    }

    int saveTransactionToFile(const Transaction* transaction, const char* filename) {
        if (!transaction || !filename) {
            fprintf(stderr, "Invalid parameters for saveTransactionToFile\n");
            return 0;
        }

        unsigned char* der_buf = NULL;
        int der_len = 0;
        if (!serializeTransactionToDER(transaction, &der_buf, &der_len)) {
            return 0;
        }

        FILE* fp = fopen(filename, "wb");
        if (!fp) {
            fprintf(stderr, "Cannot open file %s for writing\n", filename);
            free(der_buf);
            return 0;
        }

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

    Transaction* loadTransactionFromFile(const char* filename) {
        if (!filename) {
            fprintf(stderr, "Invalid filename for loadTransactionFromFile\n");
            return NULL;
        }

        FILE* fp = fopen(filename, "rb");
        if (!fp) {
            fprintf(stderr, "Cannot open file %s for reading\n", filename);
            return NULL;
        }

        fseek(fp, 0, SEEK_END);
        long file_size = ftell(fp);
        fseek(fp, 0, SEEK_SET);

        if (file_size <= 0) {
            fprintf(stderr, "Invalid file size for %s\n", filename);
            fclose(fp);
            return NULL;
        }

        unsigned char* der_buf = (unsigned char*)malloc(file_size);
        if (!der_buf) {
            fprintf(stderr, "Memory allocation failed for file buffer\n");
            fclose(fp);
            return NULL;
        }

        if (fread(der_buf, 1, file_size, fp) != file_size) {
            fprintf(stderr, "Error reading file %s\n", filename);
            free(der_buf);
            fclose(fp);
            return NULL;
        }
        fclose(fp);

        Transaction* transaction = deserializeTransactionFromDER(der_buf, file_size);
        free(der_buf);

        if (!transaction) {
            fprintf(stderr, "Failed to deserialize Transaction from file %s\n", filename);
            return NULL;
        }

        return transaction;
    }


} // namespace ASN1Structures