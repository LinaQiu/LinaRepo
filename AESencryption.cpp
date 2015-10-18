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
	extern BOOL  aes_init(aes *,int,int,char *,char *);
    extern void  aes_getreg(aes *,char *);
    extern void  aes_ecb_encrypt(aes *,MR_BYTE *);
    extern void  aes_ecb_decrypt(aes *,MR_BYTE *);
    extern mr_unsign32 aes_encrypt(aes *,char *);
    extern mr_unsign32 aes_decrypt(aes *,char *);
    extern void  aes_reset(aes *,int,char *);
    extern void  aes_end(aes *);
}
int main()
{ 
    int i,j,nk;
    aes a;
//  MR_BYTE y,x,m;
	char key[32];
	string plaintext;  //Message user want to encrypt
	char * block;      //Message without space, which could be encrypted by aes.encrypt() function in Miracl

    char iv[16];
	
	//Ask users to set some parameters first
	//Here, we ask user to choose key size, and set parameter nk(key size in byte)
	int key_chosen;
	cout<<"Please choose the key size you want(type the no.): 1. 128bits 2. 192bits 3. 256bits "<<endl;
	cin>>key_chosen;
	switch (key_chosen)
	{
	case 1:nk=16; break;
	case 2:nk=24; break;
	case 3:nk=32; break;
	default:cout<<"You need to choose a key size we provide above."<<endl;
	}

	//Here, we ask user to choose encryption mode, and set parameter a.mode
	int mode_chosen;
	cout<<"Please choose the encryption mode you want(type the no.): 1.ECB 2.CBC 3.CFB 4.OFB"<<endl;
	cin>>mode_chosen;
	switch (mode_chosen)
	{
	case 1:a.mode=MR_ECB;   break;
	case 2:a.mode=MR_CBC;   break;
	case 3:a.mode=MR_CFB4;  break;
	case 4:a.mode=MR_OFB16; break;
	default:cout<<"You need to choose a encryption mode we provide above."<<endl;
	}

	cout<<"Please type your password (encryption key): "<<endl;
	cin>>key;

    for (i=0;i<16;i++) iv[i]=i; 

	cout<<"Please type the message you want to encrypt below."<<endl;
	getline(cin,plaintext);
	
	//Now, let's transfer 
	cout<<"block= "<<block<<endl;

	int len=strlen(block);
	cout<<"Message length is "<<len<<endl;

    if (!aes_init(&a,MR_CBC,nk,key,iv))  
    {
		cout<<"Failed to Initialize."<<endl;
        return 0;
    }

	cout<<"Plaintext is "<<block<<endl;

	aes_encrypt(&a,block);
	    
	//Print out the encryption results in hexdecimal form
    printf("Encrypt= ");
	for (i=0;i<len;i++) printf("%02x",(unsigned char)block[i]);
    printf("\n");

	//Reset the aes parameters and decrypt ciphertext
    aes_reset(&a,MR_CBC,iv);
    aes_decrypt(&a,block);

	//print out the decryption results
	cout<<"Decryption result is "<<block<<endl;
	
	aes_end(&a);

	system("pause");
    return 0;
}
