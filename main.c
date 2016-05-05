/**
 * HW3 Part3 for computer security
 * Group members: John V. Flickinger, Travis Machacek
 *
 */

#include <stdio.h>
#include "file_ops.h"
#include "rsa_utils.h"
#include "utils.h"
#include "des_decrypt.h"

int debug = 0;

int main(int argc, char** argv)
{
    // parse commandline arguments
    char* cipherFile, *pKeyFile, *sessionKeyFile, *sigFile;
    int i;
    if (argc > 8) {
		for (i = 1; i < argc; i++) {
			char* arg = argv[i];
			// REQUIRED: the ciphertext file
			if (strcmp(arg, "-c") == 0) {
				i++;
				cipherFile = argv[i];
			}
			// REQUIRED: the public key
			else if (strcmp(arg, "-pubk") == 0) {
				i++;
				pKeyFile = argv[i];
			}
			// REQUIRED: the plaintext session key
			else if (strcmp(arg, "-sk") == 0) {
				i++;
				sessionKeyFile = argv[i];
			}
			// REQUIRED: the signature file
			else if (strcmp(arg, "-sig") == 0) {
				i++;
				sigFile = argv[i];
			}
			// OPTIONAL: for debugging purposes
			else if (strcmp(arg, "-d") == 0) {
				debug = 1;
			}	
			else {
			// PRINT OUT Help message
			}
		}
	} else {
		exit(1);
	}

	/*------------------------READ ALL THE FILES --------------------------*/
	char* ciphertext, *pubKeyContent, *sessionKeyContent;
	
	unsigned int cipherTextlen, pubKeylen, sessionKeylen;
	
	// store the content of all the files, and get their sizes
	ciphertext = read_file(cipherFile, &cipherTextlen);
	pubKeyContent = read_file(pKeyFile, &pubKeylen);
	sessionKeyContent = read_file(sessionKeyFile, &sessionKeylen);

	if (debug) {
	    printf("\ncipertext:\n%s\n", ciphertext);
	    printf("\nThe size of the cipertext is %d bytes\n", cipherTextlen);
	    printf("\nYour public Key:\n%s\n", pubKeyContent);
		printf("\nThe size of your public key is %d bytes\n", pubKeylen);
		printf("\nThe plaintext session key is: ");
		print_array_hex(sessionKeylen, sessionKeyContent);
	}
	
	/*-------------DERIVE IV AND KEY FROM SESSION KEY----------------------*/
	unsigned char key [8];
	unsigned char iv [8];
	derive_key_and_iv(sessionKeyContent, key, iv);
	
	/*-----------------------VERIFY THE SIGNATURE--------------------------*/
	
	if(verify_signature(pKeyFile, sigFile, ciphertext, cipherTextlen)) {
		printf("\nThe signature VERIFIED correctly\n\n");
	} else {
		printf("\nThe signature FAILED verification\n\n");
	}
	
	
	/*-----------------------DECRYPT THE CIPHERTEXT------------------------*/
	des_decrypt(ciphertext, NULL, key, iv, cipherTextlen);
	
    return 0;
}
