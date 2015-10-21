/*
This is the code for AES encryption, which implements random IV vector.
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
#include <assert.h>
#include <time.h>

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
int main()
{
	int i, j, nk;
	aes a;
	//  MR_BYTE y,x,m;
	char key[32];

	char iv[17];       //use iv[16] to store '\0'

	int buffSize = 16; // Defaultly set length of encryption&decryption block as 16 bytes

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
	case 3:
		{
			//Here, we ask user to choose the number of bytes to be processed in each encryption, then set parameter a.mode
			int CFB_mode_chosen;
			cout<<"Please choose the number of bytes you want to be processed in each encryption(type the no.): 1. 1byte 2. 2bytes 3. 4bytes"<<endl;
			cin>>CFB_mode_chosen;  
			if(CFB_mode_chosen==1)
			{
				a.mode=MR_CFB1;
				buffSize = 1; break;
			}
			else if(CFB_mode_chosen==2)
			{
				a.mode=MR_CFB2;
				buffSize = 2; break;
			}
			else if(CFB_mode_chosen==3)
			{
				a.mode=MR_CFB4;
				buffSize = 4; break;
			}
			else
			{
				cout<<"Please choose one of the number of bytes we provide above."<<endl;
				break;
			}
		}
	case 4:
		{
			//Here, we ask user to choose the number of bytes to be processed in each encryption, then set parameter a.mode
			int OFB_mode_chosen;
			cout<<"Please choose the number of bytes you want to be processed in each encryption(type the no.): 1. 1byte 2. 2bytes 3. 4bytes 4. 8bytes 5. 16bytes"<<endl;
			cin>>OFB_mode_chosen;  
			if(OFB_mode_chosen==1)
			{
				a.mode=MR_OFB1;
				buffSize = 1; break;
			}
			else if(OFB_mode_chosen==2)
			{
				a.mode=MR_OFB2;
				buffSize = 2; break;
			}
			else if(OFB_mode_chosen==3)
			{
				a.mode=MR_OFB4;
				buffSize = 4; break;
			}
			else if(OFB_mode_chosen==4)
			{
				a.mode=MR_OFB8;
				buffSize = 8; break;
			}
			else if(OFB_mode_chosen==5)
			{
				a.mode=MR_OFB16;
				buffSize = 16; break;
			}
			else
			{
				cout<<"Please choose one of the number of bytes we provide above."<<endl;
				break;
			}	
		}
	default:cout << "You need to choose a encryption mode we provide above." << endl;
	}

	cout << "Please type your password (encryption key): " << endl;
	cin >> key;

//Generat random numbers, and then set IV, using function strong_bigdig(_MIPD_ csprng *rng,int n,int b,big x)
//	for (i = 0; i<16; i++) iv[i] = i;
//----------------------------Set vector IV-------------------------------------//
 char raw[256];
 big x;
 time_t seed;
 csprng rng;
 miracl *mip=mirsys(200,256);
 x=mirvar(0);
 cout<<"Please enter a raw random string to generator a random IV vector: "<<endl;
 cin>>raw;
 getchar();
 time(&seed);
 //Initialize random number generator
 strong_init(&rng,strlen(raw),raw,(long)seed);
 //show vector IV is in hexdecimal
 mip->IOBASE=16;
 //Generator random hexdecimal number x
 strong_bigdig(&rng,64,2,x);
 //Store x as hexdecimal string into iv
 cotstr(x,iv);

 cout<<"iv= "<<iv<<endl;

//---------------------------------End----------------------------------------//

//---------------------------Get Timestamp and Nonce here---------------------//
  char timeStamp[255]={'\0'};
  char *systemTime=ctime(&seed);                       //Store system time in timeStamp
  cout<<"system time now is: "<<systemTime<<endl;
  //Generate timeStamp message: Message was sent at "systemTime". Expire data: one day after message send time above.
  strcat(timeStamp,"Message was sent at ");
  strcat(timeStamp,systemTime); 
  strcat(timeStamp,"Expire date: one day after message send time above.");

  char nonce[255]={'\0'};
  //show nonce in decimal
  mip->IOBASE=10;                                      
  //Generator nonce x using function strong_bigdig()  
  strong_bigdig(&rng,64,2,x);
  //Store x as a decimal string into mip->IOBUFF
  cotstr(x,mip->IOBUFF);
  cout<<"Nonce= "<<mip->IOBUFF<<endl;
  //Generate nonce message: Nonce: "mip->IOBUFF". End of nonce.
  strcat(nonce," Nonce: ");
  strcat(nonce,mip->IOBUFF);
  strcat(nonce,".End of nonce. Begin of message: ");

//---------------------------------End----------------------------------------//
    char *block = new char[buffSize+1];
	// aes Initilization 
	if (!aes_init(&a, a.mode, nk, key, iv))       //Check whether initilization of AES is successful
	{
		cout << "Failed to Initialize." << endl;
		return 0;
	}

	//Define a file to store encryption results in binary mode
	FILE *toStoreEncryptionResult = NULL;

	// fopen_s, safe fopen() function from Microsoft
	fopen_s(&toStoreEncryptionResult, "EncryptionResult.bin", "wb");
	if (!toStoreEncryptionResult) {
		cerr << "Can't open encrypted file to write." << endl;
		exit(EXIT_FAILURE);
	}

//----Here, we encrypt Timestamp and Nonce, and store in EncryptionResult.bin----//
	//len1 stores the length of timeStamp message
	//num1= (length of timeStamp) / buffSize
	//res1= (length of timeStamp) mod buffSize
	int num1,res1,len1;                     

	len1=strlen(timeStamp);
	num1=len1/buffSize;    
	res1=len1%buffSize;

	for(i=0;i<num1;i++)
	{
		for(j=0;j<buffSize;j++)
		{
			block[j]=timeStamp[j+i*buffSize];
		}
		block[buffSize]='\0';

		//Encrypt the first num1 blocks data in time_ptr
		aes_encrypt(&a, block);

		//Store encryption result in binary mode
		fwrite(block, sizeof(char), buffSize+1, toStoreEncryptionResult);
	}
	if(res1>0)
	{
		for(j=0;j<(buffSize+1);j++)
		{
			if(j<res1)
				block[j]=timeStamp[num1*buffSize+j];
			else
				block[j]='\0';
		}
		//Encrypt the rest part of data in time_ptr
		aes_encrypt(&a, block);

		//Store encryption result in binary mode
		fwrite(block, sizeof(char), buffSize+1, toStoreEncryptionResult);
	}
	
	//Encrypt nonce and store the result
	//len2 stores the length of nonce message
	//num2= (length of nonce) / buffSize
	//res2= (length of nonce) mod buffSize
	int num2,res2,len2;                     

	len2=strlen(nonce);
	num2=len2/buffSize;    
	res2=len2%buffSize;

	for(i=0;i<num2;i++)
	{
		for(j=0;j<buffSize;j++)
		{
			block[j]=nonce[j+i*buffSize];
		}
		block[buffSize]='\0';
		aes_encrypt(&a, block);
		fwrite(block, sizeof(char), buffSize+1, toStoreEncryptionResult);
	}
	if(res2>0)
	{
		for(j=0;j<(buffSize+1);j++)
		{
			if(j<res2)
				block[j]=nonce[num2*buffSize+j];
			else
				block[j]='\0';
		}
		aes_encrypt(&a, block);
		fwrite(block, sizeof(char), buffSize+1, toStoreEncryptionResult);
	}
	
//------------------------------------End---------------------------------------//

	cout << "Please type the message you want to encrypt below." << endl;

	//Clear buffer memory
	fflush(stdin);

	//Read data(message) from keyboard
	fgets(block, buffSize+1, stdin);

	cout << "Plaintext is ";
	while(block[0]!='\n')
	{
		
		//remove '\n' in last bit of each block (after fgets(), data in "block" looks like this: (buffSize-2) bits message+'\n'+'\0' )
		if (block[strlen(block) - 1] == '\n')
		{
			// remove '\n'
			block[strlen(block) - 1] = '\0';
		}
		
		cout<<block;
		
		//Encrypt each message block
		aes_encrypt(&a, block);

		//Store encryption result in binary mode
		fwrite(block, sizeof(char), buffSize+1, toStoreEncryptionResult);

		//Read another "buffSize" bytes data in memory buffer to encryptin "block"
		fgets(block, buffSize+1, stdin);
	}
	cout<<endl;

	//close toStoreEncryptionResult
	fclose(toStoreEncryptionResult);

	//release pointer block
	delete[] block;

	//Define a FILE* handle to read encryption results in file EncryptionResult.bin
	FILE *toReadEncryptionResult = NULL;

	//Read in binary mode
	fopen_s(&toReadEncryptionResult, "EncryptionResult.bin", "rb");
	if (!toReadEncryptionResult) {
		cerr << "Can't open encrypted file to read." << endl;
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
		//Output decryption results
		cout << encryptBlock;
	}
	cout << endl;

	// close toReadEncryptionResult
	fclose(toReadEncryptionResult);
	// release encryptBlock
	delete[] encryptBlock;

	//clean up a
	aes_end(&a);

	system("pause");
	return 0;
}
