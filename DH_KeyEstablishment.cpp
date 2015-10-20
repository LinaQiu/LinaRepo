/*
 *   Example program demonstrates 1024 bit Diffie-Hellman, El Gamal and RSA
 *   and 168 bit Elliptic Curve Diffie-Hellman 
 *
 *   Requires: big.cpp ecn.cpp
 */

#include <iostream>
#include "ecn.h"
#include "big.h"
#include <ctime>

extern "C" { FILE _iob[3] = {__iob_func()[0], __iob_func()[1], __iob_func()[2]}; }

//using namespace std;

/* large 1024 bit prime p for which (p-1)/2 is also prime */

char *primetext=(char *)
"155315526351482395991155996351231807220169644828378937433223838972232518351958838087073321845624756550146945246003790108045940383194773439496051917019892370102341378990113959561895891019716873290512815434724157588460613638202017020672756091067223336194394910765309830876066246480156617492164140095427773547319";

char *primetext1=(char *)
"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF";

/* NIST p192 bit elliptic curve prime 2#192-2#64-1 */

char *ecp=(char *)"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF";

/* elliptic curve parameter B */

char *ecb=(char *)"64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1";

/* elliptic curve - point of prime order (x,y) */

char *ecx=(char *)"188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012";
char *ecy=(char *)"07192B95FFC8DA78631011ED6B24CDD573F977A11E794811";

char *text=(char *)"MIRACL - Best multi-precision library in the World!\n";

#ifndef MR_NOFULLWIDTH
Miracl precision(500,0);
#else 
Miracl precision(500,MAXBASE);
#endif

// If MR_STATIC is defined in mirdef.h, it is assumed to be 100

//Miracl precision(120,(1<<26));

int main()
{
    int ia,ib;
    time_t seed;
    Big a,b,p,q,n,phi,pa,pb,key,e,d,m,c,x,y,k,inv,t;
//	Big p1,pa1,pb1,key1;
    Big primes[2],pm[2];
    ECn g,ea,eb;
    miracl *mip=&precision;

    time(&seed);
    irand((long)seed);   /* change parameter for different values */

    cout << "First Diffie-Hellman Key exchange .... " << endl;

	mip->IOBASE=16;
    p=primetext1;
	cout<<"test"<<endl;
//	p1=primetext1;
//	int len=strlen(primetext1);
//	cout<<"len= "<<len<<endl;
//	int len1=strlen(primetext1);
//	cout<<"len1= "<<len1<<endl;

/* offline calculations could be done quicker using Comb method
   - See brick.cpp. Note use of "truncated exponent" of 160 bits - 
   could be output from hash function SHA (see mrshs.c)             */

    cout << "\nAlice's offline calculation" << endl;        
    a=rand(160,2);

/* 3 generates the prime sub-group of size (p-1)/2 */

    pa=pow(2,a,p);             // pa =3^a mod p
//	pa1=pow(2,a,p1);

    cout << "Bob's offline calculation" << endl;        
    b=rand(160,2);
    pb=pow(2,b,p);
//	pb1=pow(2,b,p1);

    cout << "Alice calculates Key=" << endl;
    key=pow(pb,a,p);
    cout << key << endl;
/*
	cout << "Alice calculates Key1=" << endl;
	key1=pow(pb1,a,p1);
	cout << key1 << endl;
*/
//	char key_ptr[255];
//	char key_ptr1[512];
	int len_key;
//	int len_key1;

	len_key=to_binary(key,strlen(mip->IOBUFF),mip->IOBUFF,FALSE);
	cout<<"pure binary key string is "<<endl;
	for(int i=0;i<len_key;i++)
		printf("%02x",(unsigned char)mip->IOBUFF[i]);
	printf("\n");

	cout<<"len_key= "<<len_key<<endl;
/*
	len_key1=to_binary(key1,512,key_ptr1,FALSE);
	cout<<"pure binary key string is "<<endl;
	for(int i=0;i<len_key1;i++)
		printf("%02x",(unsigned char)key_ptr1[i]);
	printf("\n");

	cout<<"len_key1= "<<len_key1<<endl;
*/
	mip->IOBASE=16;
	mip->IOBUFF << key;
	cout<<"hex display of key is "<<mip->IOBUFF<<endl;
	cout<<"len of hex string of key is "<<strlen(mip->IOBUFF)<<endl;
/*
	mip->IOBASE=16;
	mip->IOBUFF << key1;
	cout<<"hex display of key is "<<mip->IOBUFF<<endl;
	cout<<"len of hex string of key is "<<strlen(mip->IOBUFF)<<endl;
	*/
	cin.get();

    cout << "Bob calculates Key=" << endl;
    key=pow(pa,b,p);
    cout << key << endl;
/*
	cout << "Bob calculates Key1=" << endl;
    key1=pow(pa1,b,p1);
    cout << key1 << endl;
	*/
	cin.get();

    cout << "Alice and Bob's keys should be the same!" << endl;

/* 
   Now Elliptic Curve version of the above.
   Curve is y^2=x^3+Ax+B mod p, where A=-3, B and p as above 
   "Primitive root" is the point (x,y) above, which is of large prime order q. 
   In this case actually
   q=FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831 
 
*/
    cout << "\nLets try that again using elliptic curves...." << endl;
    a=-3;
    mip->IOBASE=16;
    b=ecb;
    p=ecp;
    ecurve(a,b,p,MR_BEST);  // means use PROJECTIVE if possible, else AFFINE coordinates
    x=ecx;
    y=ecy;
    mip->IOBASE=10;
    g=ECn(x,y);
    ea=eb=g;

    cout << "Alice's offline calculation" << endl;        
    a=rand(160,2);
    ea*=a;
    ia=ea.get(pa); /* <ia,pa> is compressed form of public key */

    cout << "Bob's offline calculation" << endl;        
    b=rand(160,2);
    eb*=b;
    ib=eb.get(pb); /* <ib,pb> is compressed form of public key */

    cout << "Alice calculates Key=" << endl;
    eb=ECn(pb,ib);  /* decompress eb */
    eb*=a;
    eb.get(key);
    cout << key << endl;

    cout << "Bob calculates Key=" << endl;
    ea=ECn(pa,ia); /* decompress ea */
    ea*=b;
    ea.get(key);
    cout << key << endl;

    cout << "Alice and Bob's keys should be the same! (but much smaller)" << endl;


/* El Gamal's Method */

    cout << "\nTesting El Gamal's public key method" << endl;
    p=primetext;
    x=rand(160,2);
    y=pow(3,x,p);
    do 
    {
        k=rand(160,2);
    } while (gcd(p-1,k)!=1);  

    mip->IOBASE=256;  
    a=pow(3,k,p);
    b=modmult(pow(y,k,p),(Big)text,p);
    mip->IOBASE=10;
    cout << "Ciphertext= \n" << a << "\n" << b << endl;

    m=modmult(b,pow(a,p-1-x,p),p);
    mip->IOBASE=256;
    cout << "Plaintext= \n" << m << endl;
    mip->IOBASE=10;

/* RSA. Generate primes p & q. Use e=65537, and find d=1/e mod (p-1)(q-1) */

    cout << "\nNow generating 512-bit random primes p and q" << endl;
    for(;;) 
    {
        p=rand(512,2);        // random 512 bit number
        if (p%2==0) p+=1;
        while (!prime(p)) p+=2;

        q=rand(512,2);
        if (q%2==0) q+=1;
        while (!prime(q)) q+=2;

        n=p*q;

        e=65537;
        phi=(p-1)*(q-1);
        if (gcd(e,phi)!=1) continue;
        d=inverse(e,phi);
        break;
    }
    cout << p << endl;
    cout << q << endl;
    cout << "n = p.q = \n";
    cout << n << endl;

/* set up for chinese remainder thereom */

//    primes[0]=p;
//   primes[1]=q;

//    Crt chinese(2,primes);

    inv=inverse(p,q);   // precalculate this

    mip->IOBASE=256;
  
    cout << "Encrypting test string" << endl;
    c=pow((Big)text,e,n);         // c=m^e mod n
    mip->IOBASE=10;
    cout << "Ciphertext= \n";
    cout << c << endl;

    cout << "Decrypting test string" << endl;

    pm[0]=pow(c%p,d%(p-1),p);    /* get result mod p */
    pm[1]=pow(c%q,d%(q-1),q);    /* get result mod q */

    t=modmult(inv,pm[1]-pm[0],q);  // use CRT in simple way, as only 2 primes
    m=t*p+pm[0];

 //   m=chinese.eval(pm);    /* combine them using CRT */

    mip->IOBASE=256;
    cout << "Plaintext= \n";
    cout << m << endl;

	system("pause");
    return 0;
}
 

