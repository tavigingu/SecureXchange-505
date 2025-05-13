#pragma once
#ifndef ASN1_STRUCTURES_H
#define ASN1_STRUCTURES_H

#include <openssl/asn1.h>
#include <openssl/asn1t.h>

typedef struct PubKeyMac_st {
    ASN1_PRINTABLESTRING* pubKeyName;
    ASN1_OCTET_STRING* macKey;
    ASN1_OCTET_STRING* macValue;
} PubKeyMac;

DECLARE_ASN1_FUNCTIONS(PubKeyMac);

typedef struct SymElements_st {
    ASN1_INTEGER* symElementsID;
    ASN1_OCTET_STRING* symKey;
    ASN1_OCTET_STRING* iv;
} SymElements;

DECLARE_ASN1_FUNCTIONS(SymElements)

typedef struct Transaction_st {
    ASN1_INTEGER* transactionID;
    ASN1_PRINTABLESTRING* subject;
    ASN1_INTEGER* senderID;
    ASN1_INTEGER* receiverID;
    ASN1_INTEGER* symElementsID;
    ASN1_OCTET_STRING* encryptedData;
    ASN1_OCTET_STRING* transactionSign;
} Transaction;

DECLARE_ASN1_FUNCTIONS(Transaction)

namespace ASN1Structures {

    //pubkey
    int serializePubKeyMacToDER(const PubKeyMac* pubKeyMac, unsigned char** der_buf, int* der_len);
    PubKeyMac* deserializePubKeyMacFromDER(const unsigned char* der_buf, int der_len);
    int savePubKeyMacToFile(const PubKeyMac* pubKeyMac, const char* filename);
    PubKeyMac* loadPubKeyMacFromFile(const char* filename);

    //syselements
    int serializeSymElementsToDER(const SymElements* symElements, unsigned char** der_buf, int* der_len);
    SymElements* deserializeSymElementsFromDER(const unsigned char* der_buf, int der_len);
    int saveSymElementsToFile(const SymElements* symElements, const char* filename);
    SymElements* loadSymElementsFromFile(const char* filename);

    // tranzactii
    int serializeTransactionToDER(const Transaction* transaction, unsigned char** der_buf, int* der_len);
    Transaction* deserializeTransactionFromDER(const unsigned char* der_buf, int der_len);
    int saveTransactionToFile(const Transaction* transaction, const char* filename);
    Transaction* loadTransactionFromFile(const char* filename);

} 

#endif // ASN1_STRUCTURES_H

