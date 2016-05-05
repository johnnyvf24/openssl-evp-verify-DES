#include "rsa_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include "file_ops.h"

int padding = RSA_NO_PADDING;	//Didn't know exactly how to pad, so no padding was used

//Initialize openssl RSA.
RSA * initRSA(unsigned char * key,int public)
{
    RSA *rsa= NULL;
    BIO *keybio ;
    keybio = BIO_new_mem_buf(key, -1);
    if (keybio==NULL)
    {
        printf( "Failed to create key BIO");
        return 0;
    }
    if(public)
    {
        rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa,NULL, NULL);
    }
    else
    {
        rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa,NULL, NULL);
    }
 
    return rsa;
}

/**
 * @brief decrypt and get the session key from a third party public key.
 * @param enc_data, the encrypted data
 * @param data_len, the length of the encrypted data
 * @param key, the public key
 * @param decrypted, the decrypted output
 * @return the length of the decryption or -1 if it was a failure.
 */
int public_decrypt(unsigned char * enc_data, int length_of_data, unsigned char * pubKey, unsigned char *decrypted)
{
    RSA * rsa = initRSA(pubKey,1);
    return RSA_public_decrypt(length_of_data, enc_data, decrypted, rsa, padding);
}

int verify_signature(char * pubKeyFileName, char * signatureFileName, unsigned char * msg, unsigned int len) {
	OpenSSL_add_all_algorithms();
	OpenSSL_add_all_ciphers();
	OpenSSL_add_all_digests();
	
	//READ the public key.
	FILE * pf = fopen(pubKeyFileName, "r");
	EVP_PKEY *evpKey = 0;
	PEM_read_PUBKEY(pf, &evpKey, NULL, NULL);
	
	
	//get the signature
	unsigned int siglen;
	unsigned char * sig = read_file(signatureFileName, &siglen);
	
	EVP_MD_CTX *ctx;
	
	ctx = EVP_MD_CTX_create();    
	const EVP_MD* md = EVP_get_digestbyname( "SHA256" );
	
	EVP_DigestInit_ex( ctx, md, NULL );
	EVP_DigestVerifyInit( ctx, NULL, md, NULL, evpKey );
	EVP_DigestVerifyUpdate(ctx, msg, len);
	
	if ( !EVP_DigestVerifyFinal( ctx, sig, siglen)) {
		return 0;
	} else {
		return 1;
	}
	flose(pf);
	EVP_MD_CTX_destroy(ctx);
}

/**
 * @brief Derive the key and initialization vector from the session key.The key is the first 8 bytes from
 * a SHA256 hash of the sessionKey, the IV is the second 8 bytes.
 * @param session_key, only the first 8 bytes will be used.
 * @param key, the key outputted. 
 * @param iv, the initialization vector outputted.
 */
void derive_key_and_iv(unsigned char * sessionKey, unsigned char * key, unsigned char * iv) {
	OpenSSL_add_all_algorithms();
	
	unsigned char * sKey[8];
	unsigned char outHash [33];
	memcpy(sKey, sessionKey, 8);
	if(debug) print_array_hex(8, sKey);
	
	unsigned int md_len = -1;
    const EVP_MD *md = EVP_get_digestbyname("SHA256");
    if(NULL != md) {
        EVP_MD_CTX mdctx;
        EVP_MD_CTX_init(&mdctx);
        EVP_DigestInit_ex(&mdctx, md, NULL);
        EVP_DigestUpdate(&mdctx, sKey, 8);
        EVP_DigestFinal_ex(&mdctx, outHash, &md_len);
        EVP_MD_CTX_cleanup(&mdctx);
    }
	
	if(debug) {
		printf("The outputted hash is: ");
		print_array_hex(32, outHash);
	}
	
	//Use the first 8 bytes as the key
	memcpy(key, outHash, 8);
	if(debug) {
		printf("\nThe symmetric key is ");
		print_array_hex(8, key);
	}
	
	//Use the second 8 bytes as the iv
	memcpy(iv, outHash + 8, 8);
	if(debug) {
		printf("\nThe iv is ");
		print_array_hex(8, iv);
	}
}
