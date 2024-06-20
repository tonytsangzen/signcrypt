#ifndef signcrypt_tbsbr_H
#define signcrypt_tbsbr_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>

#if !defined(__clang__) && !defined(__GNUC__) && !defined(__attribute__)
#define __attribute__(X)
#endif

#define SECRETKEYBYTES 32
#define PUBLICKEYBYTES 32
#define SHAREDBYTES 32
#define SEEDBYTES 64
#define SIGNBYTES (32 + 32)
#define STATEBYTES 512

void signcrypt_keygen(unsigned char pk[PUBLICKEYBYTES], unsigned char sk[SECRETKEYBYTES]);
void signcrypt_seed_keygen(unsigned char pk[PUBLICKEYBYTES], unsigned char sk[SECRETKEYBYTES], const unsigned char seed[SEEDBYTES]);
int signcrypt_sign(unsigned char *c,  size_t *c_len,
				   const  unsigned char *info, size_t info_len,
				   const unsigned char *m, size_t m_len, 
				   const unsigned char *sender_sk, const unsigned char *recipient_pk);

int signcrypt_verify(unsigned char *m, size_t *m_len,
					 const unsigned char *info, size_t info_len, 
					 const unsigned char *c,  size_t c_len, 
					 const unsigned char *sender_pk, const unsigned char *recipient_sk);


#ifdef __cplusplus
}
#endif

#endif
