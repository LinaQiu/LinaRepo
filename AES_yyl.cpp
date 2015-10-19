#include <stdlib.h> 
#include <stdio.h>
#include <string>
#include <iostream>
#include <atlenc.h>
#include <fstream>
#include <assert.h>

using namespace std;

extern "C"
{
#include "miracl.h"
}

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
int main()
{
	int i, j, nk;
	aes a;
	//  MR_BYTE y,x,m;
	char key[32];

	char iv[16];

	int buffSize = 16; // 默认加解密长度是16字节

	//Ask users to set some parameters first
	//Here, we ask user to choose key size, and set parameter nk(key size in byte)
	int key_chosen;
	cout << "Please choose the key size you want(type the no.): 1. 128bits 2. 192bits 3. 256bits " << endl;
	cin >> key_chosen;
	switch (key_chosen)
	{
	case 1:nk = 16; break;
	case 2:nk = 24; break;
	case 3:nk = 32; break;
	default:cout << "You need to choose a key size we provide above." << endl;
	}

	//Here, we ask user to choose encryption mode, and set parameter a.mode
	int mode_chosen;
	cout << "Please choose the encryption mode you want(type the no.): 1.ECB 2.CBC 3.CFB 4.OFB" << endl;
	cin >> mode_chosen;
	switch (mode_chosen)
	{
	case 1:a.mode = MR_ECB;   break;
	case 2:a.mode = MR_CBC;   break;
	case 3:a.mode = MR_CFB4; buffSize = 4; break;
	case 4:a.mode = MR_OFB16; break;
	default:cout << "You need to choose a encryption mode we provide above." << endl;
	}

	char *block = new char[buffSize];

	cout << "Please type your password (encryption key): " << endl;
	cin >> key;

	for (i = 0; i<16; i++) iv[i] = i;

	cout << "Please type the message you want to encrypt below." << endl;

	//Clear buffer memory
	fflush(stdin);

	//Read data(message) from keyboard
	fgets(block, buffSize, stdin);

	// 初始化只用做一次，不要放到循环里面
	if (!aes_init(&a, a.mode, nk, key, iv))       //Check whether initilization of AES is successful
	{
		cout << "Failed to Initialize." << endl;
		return 0;
	}

	//Define a file to store encryption results in binary mode
	FILE *toStoreEncryptionResult = NULL;
	// fopen_s是微软的安全版fopen，linux和mac下没有同样的函数
	fopen_s(&toStoreEncryptionResult, "EncryptionResult.bin", "wb");
	if (!toStoreEncryptionResult) {
		cerr << "Can't open encrypted file to write." << endl;
		exit(EXIT_FAILURE);
	}

	while(block[0]!='\n')
	{
		//remove '\n' in last bit of each block (after fgets(), data in "block" looks like this: (buffSize-2) bits message+'\n'+'\0' )
		if (block[strlen(block) - 1] == '\n')
		{
			// remove '\n'
			block[strlen(block) - 1] = '\0';
		}
		cout << "Plaintext is " << block << endl;

		aes_encrypt(&a, block);

		//Store encryption result in binary mode
		fwrite(block, sizeof(char), buffSize, toStoreEncryptionResult);

		// aes_decrypt(&a, block);

		//print out the decryption results
		// cout << "Decryption result is " << block << endl;
		fgets(block, buffSize, stdin);
	}

	//记得关闭toStoreEncryptionResult
	fclose(toStoreEncryptionResult);

	//释放block
	delete[] block;

	FILE *toReadEncryptionResult = NULL;

	fopen_s(&toReadEncryptionResult, "EncryptionResult.bin", "rb");
	if (!toReadEncryptionResult) {
		cerr << "Can't open encrypted file to read." << endl;
		exit(EXIT_FAILURE);
	}
	fseek(toReadEncryptionResult, 0, SEEK_END);
	int fileSize = ftell(toReadEncryptionResult);
	fseek(toReadEncryptionResult, 0, SEEK_SET);

	// encryptBlock是用于解密的读取缓存，一次读buffSize个字节
	char *encryptBlock = new char[buffSize];

	// 解密之前reset一下AES的param
	aes_reset(&a, a.mode, iv);

	cout << "Decryption result is ";
	// 一次读取buffSize个字节，直到读到文件那么大
	// 文件的大小肯定是buffSize的倍数字节，因为之前写入的就是buffSize的倍数字节
	// i表示已经读取的字节数量
	for (int i = 0; i != fileSize; i += buffSize) {
		fread(encryptBlock, sizeof(char), buffSize, toReadEncryptionResult);
		aes_decrypt(&a, encryptBlock);
		// 解密出来什么就直接输出什么，因为换行符之类的也被加密了
		cout << encryptBlock;
	}
	cout << endl;

	// 记得关闭toReadEncryptionResult
	fclose(toReadEncryptionResult);
	// 释放encryptBlock
	delete[] encryptBlock;

	//同一个程序只用初始化和结束同一个结构a一次
	aes_end(&a);

	system("pause");
	return 0;
}
