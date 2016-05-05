#ifndef DES_DECRYPT_H_INCLUDED
#define DES_DECRYPT_H_INCLUDED

extern int debug;

void des_decrypt(char * ciphertext, char * writeFileName, char * key, char * iv, unsigned int cipherlen);
void des_decrypt_chunk(unsigned char key [], unsigned char C [], unsigned char ret []);
void expansionPermutation(unsigned char datablock[], unsigned char Kn[], unsigned char ret[]);
void initialPermutation(unsigned char M [], unsigned char InitPermutation[]);
void createSubKeys(unsigned char key[], unsigned char K[][6]);

#endif
