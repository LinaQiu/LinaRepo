/*
 *   Code for Diffie-Hellman Key Establishment using 2048 bit prime
 *
 *   Requires: big.cpp ecn.cpp
 */

#include <iostream>
#include <stdlib.h> 
#include <stdio.h>
#include <string>
#include "ecn.h"
#include "big.h"
#include <ctime>

extern "C"
{
#include "miracl.h"
}

using namespace std;

extern "C" { FILE _iob[3] = {__iob_func()[0], __iob_func()[1], __iob_func()[2]}; }

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

//char *DH_KeyEstablishment()
int main()
{
    time_t seed;
    Big a,b,p,q,pa,pb,key;
   
    miracl *mip=&precision;

    time(&seed);
    irand((long)seed);   /* change parameter for different values */

    cout << "First Diffie-Hellman Key exchange .... " << endl;

	mip->IOBASE=16;
    p=primetext;

//	int primetext_len=strlen(primetext);
//	cout<<"primetext_len= "<<primetext_len<<endl;

/* offline calculations could be done quicker using Comb method
   - See brick.cpp. Note use of "truncated exponent" of 160 bits - 
   could be output from hash function SHA (see mrshs.c)             */

    cout << "\nClient's offline calculation" << endl;        
    a=rand(160,2);

/* 2 generates the prime sub-group of size (p-1)/2 */

    pa=pow(2,a,p);             // pa =2^a mod p

    cout << "Server's offline calculation" << endl;        
    b=rand(160,2);

    pb=pow(2,b,p);

    cout << "Client calculates Key=" << endl;
    key=pow(pb,a,p);
    cout << key << endl;
	cout<<"key[0]= "<<key[0]<<endl;
	/*
	int key_len;
	
	key_len=to_binary(key,strlen(mip->IOBUFF),mip->IOBUFF,FALSE);
	cout<<"pure binary key string is "<<endl;
	for(int i=0;i<key_len;i++)
		printf("%02x",(unsigned char)mip->IOBUFF[i]);
	printf("\n");
	cout<<"key_len= "<<key_len<<endl;
	*/

	mip->IOBASE=16;
	mip->IOBUFF << key;
	cout<<"hex display of key is: "<<endl<<mip->IOBUFF<<endl;
	cout<<"len of hex string of key is "<<strlen(mip->IOBUFF)<<endl;
	
	//Here, client begins to hash the long session key, to get 32bytes new session key for AES encryption
    char hash_c[32];
    int i;
    sha256 sh;
    shs256_init(&sh);
	for (i=0;mip->IOBUFF[i]!=0;i++) shs256_process(&sh,mip->IOBUFF[i]);
    shs256_hash(&sh,hash_c);    
    for (i=0;i<32;i++) printf("%02x",(unsigned char)hash_c[i]);
    printf("\n");

	//server calculates his key
	cout << "Server calculates Key=" << endl;
    key=pow(pa,b,p);
    cout << key << endl;

	//Here, server begins to hash the long session key, to get 32bytes new session key for AES encryption
    char hash_s[32];
//    int i;
//    sha256 sh;
    shs256_init(&sh);
	for (i=0;mip->IOBUFF[i]!=0;i++) shs256_process(&sh,mip->IOBUFF[i]);
    shs256_hash(&sh,hash_s);    
    for (i=0;i<32;i++) printf("%02x",(unsigned char)hash_s[i]);
    printf("\n");

//////--------------------Client and Server finished to create key using 2048 bit prime--------------//////
	
	
    cout << "Alice and Bob's keys should be the same!" << endl;

	system("pause");
    return 0;
}
 

