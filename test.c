#include "signcrypt.h"
#include <sodium.h>
#include <stdio.h>
#include <string.h>


void  WriteFile(const char* path, char* data, size_t len){

    FILE *out = fopen(path, "w");
    if(!out){
        printf("Unable write to output file!\n");
    }else{
        fwrite(data, 1, len, out);
        printf("done!\n");
    }

    fclose(out);
}

void hex_dump(const char* lable, const void* buf, int len){
    int lines = (len + 15)/16;
    uint8_t *p = (uint8_t *)buf;

    printf("----:    %s    \n", lable);
    for(int l = 0; l < lines; l++){
        printf("%04X: ", l * 16);
        for(int col = 0; col < 16; col++){
            int idx = l * 16 + col;
            if(idx < len)
                printf("%02x ", p[idx]);
            else
                printf("   ");
        }
        printf(": [");
        for(int col = 0; col < 16; col++){
            int idx = l * 16 + col;
            if(idx < len)
                if(p[idx] < 127 && p[idx] >= 32)
                    printf("%c", p[idx]);
                else
                    printf(".");
            else
                printf(" ");
        }
        printf("]\n");
    }
}

#define HEX_DUMP(x, l)  hex_dump(#x, x, l)
int main(void)
{
    unsigned char sender_pk[PUBLICKEYBYTES];
    unsigned char sender_sk[SECRETKEYBYTES];
    unsigned char recipient_pk[PUBLICKEYBYTES];
    unsigned char recipient_sk[SECRETKEYBYTES];
	int ret;
    unsigned char m[32] = {0};
    unsigned char c[sizeof m + SIGNBYTES];

	for(int i = 0; i< sizeof(m); i++){
		m[i] = 'a' + i % 26;
	}

    /* in this example, we simply use the encryption nonce as the info */
    if (sodium_init() != 0) {
        return 1;
    }

    signcrypt_keygen(sender_pk, sender_sk);
    signcrypt_keygen(recipient_pk, recipient_sk);

	unsigned char info[8];
	sprintf(info, "test");

	printf("sender-side\n");
	size_t c_len = sizeof c;
	ret = signcrypt_sign(c, &c_len, info, strlen(info), m, sizeof m, sender_sk, recipient_pk);
	printf("ret : %d\n", ret);
	HEX_DUMP(c, c_len);

	memset(m, 0, sizeof m);
	//WriteFile("out.bin", c, c_len);

    /* recipient-side */
	printf("recipient-side\n");
	size_t m_len = sizeof m;
	ret = signcrypt_verify(m, &m_len, info, strlen(info), c, c_len, sender_pk, recipient_sk);
	printf("ret : %d\n", ret);

	HEX_DUMP(m, sizeof m);
    return 0;
}
