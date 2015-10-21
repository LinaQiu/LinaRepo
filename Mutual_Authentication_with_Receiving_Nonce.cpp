#include <stdlib.h> 
#include <stdio.h>
#include <string>
#include <iostream>
#include <fstream>
#include <time.h>
#include "ecn.h"
#include "big.h"
#include <winsock2.h>

#pragma comment(lib,"ws2_32.lib") //Winsock Library

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
	extern void macKey(char **C_S_Mac_key, char *password);
}

/* large 2048 bit prime p for which (p-1)/2 is also prime, we found it from RFC 3526.
 * Check the link below to see RFC 3526
 * <http://tools.ietf.org/html/rfc3526#page-3>
 */

char *primetext=(char *)
"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF";

#ifndef MR_NOFULLWIDTH
Miracl precision(500,0);
#else 
Miracl precision(500,MAXBASE);
#endif

// If MR_STATIC is defined in mirdef.h, it is assumed to be 100

//Miracl precision(120,(1<<26));

char genIV();
int mutualAuthenticationRecvNonce(char *systemType,int mode,int buffSize,int keySize,char *key,SOCKET s,char *iv,char *recvNonce)
{
	int i, j, nk;
	aes a;

//	char iv[17];       //use iv[16] to store '\0'

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

//Generat random numbers, and then set IV, using function strong_bigdig(_MIPD_ csprng *rng,int n,int b,big x)
//	for (i = 0; i<16; i++) iv[i] = i;
//----------------------------Set vector IV-------------------------------------//
 
 iv=genIV();

//---------------------------------End----------------------------------------//

//---------------------------Get Timestamp and Nonce here---------------------//
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
  char nonce[255]={'\0'};
  //show nonce in decimal
  mip->IOBASE=10;                                      
  //Generator nonce x using function strong_bigdig()  
  strong_bigdig(&rng,64,2,x);
  //Store x as a decimal string into mip->IOBUFF
  cotstr(x,mip->IOBUFF);
  cout<<"Nonce: "<<mip->IOBUFF<<endl;
  //Generate nonce message: Nonce: "mip->IOBUFF". End of nonce.
  strcat(nonce," Nonce: ");
  strcat(nonce,mip->IOBUFF);
  strcat(nonce,".End of nonce. The nonce I received is ");
  strcat(nonce,recvNonce);                                 //Add received nonce into the message
  strcat(nonce,".Begin of message: "); 
 
  char timeStamp[255]={'\0'};
  char *systemTime=ctime(&seed);                       //Store system time in timeStamp
  cout<<"Timestamp: "<<systemTime<<endl;
  //Generate timeStamp message: Message was sent at "systemTime". Expire data: one day after message send time above.
  strcat(timeStamp,"Message was sent at ");
  strcat(timeStamp,systemTime); 
  strcat(timeStamp,"Expire date: one day after message send time above.");
  
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
		//Send encryption result(binary mode) to server/client
		send(s,block,buffSize+1,0);
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

		//Send encryption result(binary mode) to server/client
		send(s,block,buffSize+1,0);
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
	
		//Send encryption result(binary mode) to server/client
		send(s,block,buffSize+1,0);
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

		//Send encryption result(binary mode) to server/client
		send(s,block,buffSize+1,0);
	}
	
//------------------------------------End---------------------------------------//

	cout <<"Please type your name and the message you want to send to server below." << endl;

	//Clear buffer memory
	fflush(stdin);

	//Read data(message) from keyboard
	fgets(block, buffSize+1, stdin);

	cout << "Encrypted Message for authentication is ";
	while(block[0]!='\n')
	{
		
		//remove '\n' in last bit of each block (after fgets(), data in "block" looks like this: (buffSize-2) bits message+'\n'+'\0' )
		if (block[strlen(block) - 1] == '\n')
		{
			// remove '\n'
			block[strlen(block) - 1] = '\0';
		}
		
		cout<<block<<endl;
		
		//Encrypt each message block
		aes_encrypt(&a, block);

		//Store encryption result in binary mode
		fwrite(block, sizeof(char), buffSize+1, toStoreEncryptionResult);

        //Send encryption result(binary mode) to server/client
		send(s,block,buffSize+1,0);

		//Read another "buffSize" bytes data in memory buffer to encryptin "block"
		fgets(block, buffSize+1, stdin);
	}
	cout<<endl;

	//close toStoreEncryptionResult
	fclose(toStoreEncryptionResult);

	//release pointer block
	delete[] block;

	//clean up a
	aes_end(&a);
	//----------------------------------------------------------------------------------------------------//
	//Here, we begin to read the encryption file, and hash it.
	FILE *toReadEncryptionForHash =NULL;
	//Read in binary mode
	fopen_s(&toReadEncryptionForHash, "EncryptionResult.bin", "rb");
	if (!toReadEncryptionForHash) {
		cerr << "Can't open encrypted file to read." << endl;
		exit(EXIT_FAILURE);
	}

	//Compute the length of encryption results
	fseek(toReadEncryptionForHash, 0, SEEK_END);
	int fileSizeForHash = ftell(toReadEncryptionForHash);
	fseek(toReadEncryptionForHash, 0, SEEK_SET);

	// Define a buffer hashBlock, used to read ciphertext in memory buffer while decrypting
	// Read "buffSize" bytes ciphertext each time

	char *hashBlock = new char[buffSize+1];

	// Each time, read buffSize bytes ciphertext, until read to the end of EncryptionResult.bin
	// i stands for how many bytes we have read
	for (int i = 0; i != fileSizeForHash; i += (buffSize+1)) {
		fread(hashBlock, sizeof(char), buffSize+1, toReadEncryptionForHash);
		//Output data read from encryptionResult in hexdecimal mode
		if(i==0)
		{
			memcpy(mip->IOBUFF,hashBlock,buffSize);
		}
		else
			strcat(mip->IOBUFF,hashBlock);
	}
	cout<<endl;
	cout<<"Encryption Results for authentication message you send: "<<endl;
	for(j=0;j<strlen(mip->IOBUFF);j++)
	{
		printf("%02x",(unsigned char)mip->IOBUFF[j]);
	}
	cout << endl;

	fclose(toReadEncryptionForHash);
	delete []hashBlock;

//------------------------------Here, we begin to hash, both Message and password(as MAC_key).---------------------------------//
//Call function macKey() to computer Client_write_MAC_key and Server_write_MAC_key, then store them in char *MACKey[2]
	char *MACKey[2];
	macKey(MACKey, key);
//According to the system type, we choose to append corresponding MAC key to mip->IOBUFF(encrypted message)
	if(systemType=="Client")
		strcat(mip->IOBUFF,MACKey[0]);
	else if(systemType=="Server")
		strcat(mip->IOBUFF,MACKey[1]);

	//Computer HMAC value for encrypted message
	char hash[32];
    sha256 sh;
    shs256_init(&sh);
    for (i=0;mip->IOBUFF[i]!=0;i++) shs256_process(&sh,mip->IOBUFF[i]);
    shs256_hash(&sh,hash);    

	cout<<"HMAC of the encrypted message you send: "<<endl;
    for (i=0;i<32;i++) printf("%02x",(unsigned char)hash[i]);
    printf("\n");

	//Send hash value(binary mode) to server/client
	send(s,hash,32,0);

	return 0;
}