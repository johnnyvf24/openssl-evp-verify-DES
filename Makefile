all:
	gcc -o DecAndVerify des_decrypt.c file_ops.c rsa_utils.c utils.c main.c des_key_functions.c bitwise_operations.c -lcrypto
