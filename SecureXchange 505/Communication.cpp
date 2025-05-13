#include "Communication.h"


unsigned char* Communication::create_data_to_sign(int sym_id, int trans_id, int sender_id, int recv_id,
    const char* subject, const unsigned char* remainder_bytes,
    const unsigned char* encrypted_data, const char* message,
    int* out_len)
{
	
    int subject_len = strlen(subject);
    int message_len = strlen(message);

    int encrypted_len = strlen((const char*)encrypted_data);

    int total_len = 4 * sizeof(int) + subject_len + 16 + encrypted_len + message_len;
    unsigned char* buffer = (unsigned char*)malloc(total_len);
    if (!buffer) return NULL;

    int offset = 0;
    memcpy(buffer + offset, &sym_id, sizeof(int));     offset += sizeof(int);
    memcpy(buffer + offset, &trans_id, sizeof(int));   offset += sizeof(int);
    memcpy(buffer + offset, &sender_id, sizeof(int));  offset += sizeof(int);
    memcpy(buffer + offset, &recv_id, sizeof(int));    offset += sizeof(int);
    memcpy(buffer + offset, subject, subject_len);     offset += subject_len;
    memcpy(buffer + offset, remainder_bytes, 16);      offset += 16;
    memcpy(buffer + offset, encrypted_data, encrypted_len); offset += encrypted_len;
    memcpy(buffer + offset, message, message_len);     offset += message_len;

    *out_len = total_len;
    return buffer;
}


