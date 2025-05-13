#pragma once
#include "Entity.h"
#include "ASN1Structures.h"


class Communication
{
public:
	Communication(Entity& sender, Entity& receiver)
		:entity_A(sender), entity_B(receiver) { }


    void __trust_me_bro_transaction__(const char* message, const char* subject)
    {
        if (!message || !subject) {
            fprintf(stderr, "Parametrii mesajului sau subiectului sunt nuli!\n");
            return;
        }

        //  generarea cheilor entitatilor
        entity_A.generateKeys("parola_bob");
        entity_B.generateKeys("parola_alice");

        // validarea cheilor
        if (!entity_A.validatePublicKey(entity_B.getPublicKeyFile(), entity_B.getMacFile())) {
            fprintf(stderr, "Validarea cheii publice a entității B a eșuat!\n");
            return;
        }

        if (!entity_B.validatePublicKey(entity_A.getPublicKeyFile(), entity_A.getMacFile())) {
            fprintf(stderr, "Validarea cheii publice a entității A a eșuat!\n");
            return;
        }

        // ECDH handshake
        unsigned char* coordX = (unsigned char*)malloc(sizeof(unsigned char) * 32);
        unsigned char* coordY = (unsigned char*)malloc(sizeof(unsigned char) * 32);
        if (!coordX || !coordY) {
            fprintf(stderr, "Alocarea memoriei pentru coordonate a eșuat!\n");
            free(coordX);
            free(coordY);
            return;
        }

        if (!entity_A.ECDHKeyExchange(entity_B, &coordX, &coordY)) {
            fprintf(stderr, "Schimbul de chei ECDH a eșuat!\n");
            free(coordX);
            free(coordY);
            return;
        }

        // derivarea cheii simetrice
        unsigned char* remainder_bytes = (unsigned char*)malloc(sizeof(unsigned char) * 32);
        

        char sym_file[256];
        snprintf(sym_file, sizeof(sym_file), "sys_elements_%s_to_%s.der", entity_A.getName(), entity_B.getName());
        int sym_id = entity_A.deriveSymmetricKey(sym_file,coordX, coordY, &remainder_bytes);
        if (sym_id == -1) {
            fprintf(stderr, "Derivarea cheii simetrice a eșuat!\n");
            free(coordX);
            free(coordY);
            free(remainder_bytes);
            return;
        }

  
        // criptarea datelor folosind cheia simetrica cu aes-fancy-ofb
        unsigned char* encrypted_data = entity_A.encryptData(sym_file, message, strlen(message));
        if (!encrypted_data) {
            fprintf(stderr, "Criptarea datelor a eșuat!\n");
            free(coordX);
            free(coordY);
            free(remainder_bytes);
            return;
        }
        size_t encrypted_data_len = strlen(message); // Corect, nu strlen(encrypted_data)

        // Preluăm toate datele tranzacției pentru a fi semnate
        int trans_id = IDGenerator::generate();
        char* t_subject = strdup(subject);
        if (!t_subject) {
            fprintf(stderr, "Alocarea memoriei pentru t_subject a eșuat!\n");
            free(coordX);
            free(coordY);
            free(remainder_bytes);
            free(encrypted_data);
            return;
        }
        int sender_id = entity_A.getID();
        int recv_id = entity_B.getID();

        // Le serializăm pentru a aplica semnătura
        int len;
        unsigned char* data_to_sign = create_data_to_sign(
            sym_id, trans_id, sender_id, recv_id,
            t_subject, remainder_bytes,
            encrypted_data, message,
            &len);
        if (!data_to_sign) {
            fprintf(stderr, "Crearea datelor pentru semnare a eșuat!\n");
            free(coordX);
            free(coordY);
            free(remainder_bytes);
            free(encrypted_data);
            free(t_subject);
            return;
        }

        // Semnăm datele
        unsigned char* signature = NULL;
        size_t signature_len = 0;
        if (!entity_A.signData(data_to_sign, len, &signature, &signature_len) || !signature) {
            fprintf(stderr, "Semnarea datelor a eșuat!\n");
            free(coordX);
            free(coordY);
            free(remainder_bytes);
            free(encrypted_data);
            free(t_subject);
            free(data_to_sign);
            return;
        }

        Transaction* transaction = Transaction_new();
        if (!transaction) {
            fprintf(stderr, "Alocarea structurii Transaction a eșuat!\n");
            free(coordX);
            free(coordY);
            free(remainder_bytes);
            free(encrypted_data);
            free(t_subject);
            free(data_to_sign);
            free(signature);
            return;
        }

        if (!ASN1_INTEGER_set(transaction->transactionID, trans_id) ||
            !ASN1_STRING_set(transaction->subject, (unsigned char*)t_subject, strlen(t_subject)) ||
            !ASN1_INTEGER_set(transaction->senderID, sender_id) ||
            !ASN1_INTEGER_set(transaction->receiverID, recv_id) ||
            !ASN1_INTEGER_set(transaction->symElementsID, sym_id) ||
            !ASN1_OCTET_STRING_set(transaction->encryptedData, encrypted_data, encrypted_data_len) ||
            !ASN1_OCTET_STRING_set(transaction->transactionSign, signature, signature_len)) {
            fprintf(stderr, "Setarea câmpurilor Transaction a eșuat!\n");
            Transaction_free(transaction);
            free(coordX);
            free(coordY);
            free(remainder_bytes);
            free(encrypted_data);
            free(t_subject);
            free(data_to_sign);
            free(signature);
            return;
        }

        char filename[256];
        snprintf(filename, sizeof(filename), "transaction_%s_to_%s.der", entity_A.getName(), entity_B.getName());
        if (!ASN1Structures::saveTransactionToFile(transaction, filename)) {
            fprintf(stderr, "Salvarea tranzacției în fișier a eșuat!\n");
            Transaction_free(transaction);
            free(coordX);
            free(coordY);
            free(remainder_bytes);
            free(encrypted_data);
            free(t_subject);
            free(data_to_sign);
            free(signature);
            return;
        }

        Transaction_free(transaction);
        free(coordX);
        free(coordY);
        free(remainder_bytes);
        //free(encrypted_data);
        OPENSSL_free(encrypted_data);
        free(t_subject);
        free(data_to_sign);
        free(signature);
    }



private:
	Entity& entity_A;
	Entity& entity_B;

	unsigned char* create_data_to_sign(
		int sym_id, int trans_id, int sender_id, int recv_id,
		const char* subject, const unsigned char* remainder_bytes,
		const unsigned char* encrypted_data, const char* message,
		int* out_len);

};

