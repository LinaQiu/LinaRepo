/*
This is the code for AES decryption, which needs parameters: IV vector, key, .
And encrypted plaintext includes a timeStamp, a random generated nonce, and the message. 

Required files:
"mraes.c" 
"mrstrong.c"

Required library:
"miracl.lib"
*/

#include <stdlib.h> 
#include <stdio.h>
#include <string>
#include <iostream>
#include <fstream>
#include <time.h>
#include "ecn.h"
#include "big.h"

using namespace std;

extern "C"
{
#include "miracl.h"
}

extern "C" { FILE _iob[3] = {__iob_func()[0], __iob_func()[1], __iob_func()[2]}; }

#define MR_WORD mr_unsign32

/* this is fixed */
#define NB 4

extern "C"
{
	extern BOOL  aes_init(aes *, int, int, char *, char *);
	extern void  aes_getreg(aes *, char *);
	extern void  aes_ecb_encrypt(aes *, MR_BYTE *);
	extern void  aes_ecb_decrypt(aes *, MR_BYTE *);
	extern mr_unsign32 aes_encrypt(aes *, char *);
	extern mr_unsign32 aes_decrypt(aes *, char *);
	extern void   aes_reset(aes *, int, char *);
	extern void  aes_end(aes *);
}


int aesDecryption(int mode,int buffSize,int keySize,char *key,char *iv)
{
	int i, j, nk;
	aes a;
	
	//Set key size here
	switch (keySize)
	{
	case 1:nk = 16; break;
	case 2:nk = 24; break;
	case 3:nk = 32; break;
	default:;
	}

	//Set encryption mode
	switch (mode)
	{
	case 1:a.mode = MR_ECB;   break;
	case 2:a.mode = MR_CBC;   break;
	case 3:a.mode = MR_CFB4;  break;
	case 4:a.mode = MR_OFB16; break;
	default:;
	}

	// aes Initilization/Reset
	if (!aes_init(&a, a.mode, nk, key, iv))       //Check whether initilization of AES is successful
	{
		cout << "Failed to Initialize." << endl;
		return 0;
	} 

	//Define a FILE* handle to read encryption results in file EncryptionResult.bin
	FILE *toReadEncryptionResult = NULL;

	//Read in binary mode
	fopen_s(&toReadEncryptionResult, "EncryptionResult.bin", "rb");
	if (!toReadEncryptionResult) {
		cerr << "Can't open encrypted file to read." << endl;
		exit(EXIT_FAILURE);
	}

	//Define a FILE* handle to store the decryption results in file DecryptionResult.txt
	FILE *toStoreDecryptionResult = NULL;

	//fopen_s, safe fopen() function from Microsoft
	fopen_s(&toStoreDecryptionResult,"DecryptionResult.txt","w");
	if (!toStoreDecryptionResult) {
		cerr << "Can't open decryption file to write." << endl;
		exit(EXIT_FAILURE);
	}

	//Compute the length of encryption results
	fseek(toReadEncryptionResult, 0, SEEK_END);
	int fileSize = ftell(toReadEncryptionResult);
	fseek(toReadEncryptionResult, 0, SEEK_SET);

	// Define a buffer encryptBlock, used to read ciphertext in memory buffer while decrypting
	// Read "buffSize" bytes ciphertext each time
	char *encryptBlock = new char[buffSize+1];

	//IMPORTANT!!!
	// Before decryption, reset AES parameters 
	aes_reset(&a, a.mode, iv);

	cout << "Decryption result is ";
	// Each time, read buffSize bytes ciphertext, until read to the end of EncryptionResult.bin
	// i stands for how many bytes we have read
	for (int i = 0; i != fileSize; i += (buffSize+1)) {
		fread(encryptBlock, sizeof(char), buffSize+1, toReadEncryptionResult);
		aes_decrypt(&a, encryptBlock);
		//Output decryption results into file toStoreDecryptionResult.txt
		fwrite(encryptBlock, sizeof(char), buffSize+1, toStoreDecryptionResult);
		//Display decryption results in terminal
		cout << encryptBlock;
	}
	cout << endl;

	// close toReadEncryptionResult
	fclose(toReadEncryptionResult);
	// release encryptBlock
	delete[] encryptBlock;

	//clean up a
	aes_end(&a);

	return 0;
}