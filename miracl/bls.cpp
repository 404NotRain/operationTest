/*
   Boneh-Lynn-Shacham short signature

   Compile with modules as specified in the selected header file

   For MR_PAIRING_CP curve
   cl /O2 /GX bls.cpp cp_pair.cpp zzn2.cpp big.cpp zzn.cpp ecn.cpp miracl.lib
   (Note this really doesn't make much sense as the signature will not be "short")

   For MR_PAIRING_MNT curve
   cl /O2 /GX bls.cpp mnt_pair.cpp zzn6a.cpp ecn3.cpp zzn3.cpp zzn2.cpp big.cpp zzn.cpp ecn.cpp miracl.lib
	
   For MR_PAIRING_BN curve
   cl /O2 /GX bls.cpp bn_pair.cpp zzn12a.cpp ecn2.cpp zzn4.cpp zzn2.cpp big.cpp zzn.cpp ecn.cpp miracl.lib

   For MR_PAIRING_KSS curve
   cl /O2 /GX bls.cpp kss_pair.cpp zzn18.cpp zzn6.cpp ecn3.cpp zzn3.cpp big.cpp zzn.cpp ecn.cpp miracl.lib

   For MR_PAIRING_BLS curve
   cl /O2 /GX bls.cpp bls_pair.cpp zzn24.cpp zzn8.cpp zzn4.cpp zzn2.cpp ecn4.cpp big.cpp zzn.cpp ecn.cpp miracl.lib

   Test program 
*/

#include <iostream>
#include <ctime>

//********* choose just one of these pairs **********
//#define MR_PAIRING_CP      // AES-80 security   
//#define AES_SECURITY 80

//#define MR_PAIRING_MNT	// AES-80 security
//#define AES_SECURITY 80

#define MR_PAIRING_BN    // AES-128 or AES-192 security
#define AES_SECURITY 128
//#define AES_SECURITY 192

//#define MR_PAIRING_KSS    // AES-192 security
//#define AES_SECURITY 192

//#define MR_PAIRING_BLS    // AES-256 security
//#define AES_SECURITY 256
//*********************************************

#include "pairing_3.h"

struct Big2d {
    Big m[2][2];
};

Big2d matmul(Big2d m1, Big2d m2, Big mod) {
    Big2d result;
    Big tmp;
    for(int i = 0; i < 2; i++)
        for(int j = 0; j < 2; j++){
            result.m[i][j].operator=(modmult(tmp.operator=(m1.m[i][0]),m2.m[0][j],mod));
            result.m[i][j].operator+=(modmult(tmp.operator=(m1.m[i][1]),m2.m[1][j],mod));
        }

    return result;

}

Big T(Big p, Big x, Big mod) {
    Big tmp;
    Big2d A,Ap;
    A.m[0][0] = 0;
    A.m[0][1] = 1;
    A.m[1][0] = -1;
    A.m[1][1] = modmult(tmp.operator=(2),x,mod);

    Ap.m[0][0] = 0;
    Ap.m[0][1] = 1;
    Ap.m[1][0] = -1;
    Ap.m[1][1] = modmult(tmp.operator=(2),x,mod);

    for(int i = bits(p)-1; i > 0; i--) {
        Ap = matmul(Ap, Ap, mod);
        if(bit(p,i-1)) {
            Ap = matmul(Ap, A, mod);
        }
    }
    return Ap.m[0][0].operator+=(modmult(Ap.m[0][1],x,mod));
}

void sha256_test() {
    //char test[]="abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    char test[] = "7C55E32520935B3B2C5B193AFD2D1D11";
    char hash[32];
    sha256 sh;
    clock_t start = clock();
    shs256_init(&sh);
    for (int i=0;test[i]!=0;i++)
        shs256_process(&sh,test[i]);

    shs256_hash(&sh,hash);
    clock_t end = clock();
    double msecs = ((double) (end - start)) * 1000 / CLOCKS_PER_SEC;
    cout << "sha256 time -> " << msecs << endl;
}

void aes_test() {
    int i,j,nk = 16, NB = 4;
    aes a;
    MR_BYTE y,x,m;
    char key[32];
    char block[16];
    char iv[16];
    for (i=0;i<32;i++) key[i]=i;
    key[0]=1;
    for (i=0;i<16;i++) iv[i]=i;
    for (i=0;i<16;i++) block[i]=i;

    //printf("\nKey Size= %d bits\n", nk * 8);
    clock_t start = clock();
    if (!aes_init(&a, MR_ECB, nk, key, iv)) {
        printf("Failed to Initialize\n");
    }

    //printf("Plain=   ");
    //for (i = 0; i < 4 * NB; i++) printf("%02x", block[i]);
    //printf("\n");

    aes_encrypt(&a, block);
    clock_t end = clock();
    double msecs = ((double) (end - start)) * 1000 / CLOCKS_PER_SEC;
    cout << "aes time -> " << msecs << endl;
    //printf("Encrypt= ");
    //for (i = 0; i < 4 * NB; i++) printf("%02x", (unsigned char) block[i]);
    //printf("\n");
    aes_reset(&a, MR_CBC, iv);
    aes_decrypt(&a, block);
    //printf("Decrypt= ");
    //for (i = 0; i < 4 * NB; i++) printf("%02x", block[i]);
    //printf("\n");

    aes_end(&a);
}

void random_hex(char str[], int length)
{
    //hexadecimal characters
    char hex_characters[]={'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};
    int i;
    for(i=0;i<length;i++)
    {
        str[i]=hex_characters[rand()%16];
    }
    str[length] = 0;
}


int main()
{   
	PFC pfc(AES_SECURITY);  // initialise pairing-friendly curve

	G2 Q,V;
	G1 S,R;
	int lsb;
	Big s,X;
	time_t seed;

	time(&seed);
    irand((long)seed);

// Create system-wide G2 constant
	pfc.random(Q);
	pfc.random(s);    // private key

	clock_t start, end;
	double msecs;
	start = clock();
	V=pfc.mult(Q,s);  // public key
	end = clock();
	msecs = ((double) (end - start)) * 1000 / CLOCKS_PER_SEC;
	cout << "pfc.mult time -> " << msecs << endl;

// signature
	pfc.hash_and_map(R,(char *)"Test Message to sign");
	S=pfc.mult(R,s);

	lsb=S.g.get(X);   // signature is lsb bit and X

	cout << "Signature= " << lsb << " " << X << endl;

// verification	- first recover full point S
	if (!S.g.set(X,1-lsb))
	{
		cout << "Signature is invalid" << endl;
		exit(0);
	}
	pfc.hash_and_map(R,(char *)"Test Message to sign");


// Observe that Q is a constant
// Interesting that this optimization doesn't work for the Tate pairing, only the Ate

	pfc.precomp_for_pairing(Q);

	G1 *g1[2];
	G2 *g2[2];
	g1[0]=&S; g1[1]=&R;
	g2[0]=&Q; g2[1]=&V;

	start = clock();
	GT gt = pfc.pairing(*g2[0], *g1[0]);
	end = clock();
	msecs = ((double) (end - start)) * 1000 / CLOCKS_PER_SEC;
	cout << "pfc.pairing time -> " << msecs << endl;

	start = clock();
	pfc.power(gt,s);
	end = clock();
	msecs = ((double) (end - start)) * 1000 / CLOCKS_PER_SEC;
	cout << "pfc.power time -> " << msecs << endl;


    //cout << T(10,678,*(pfc.mod)) << endl;

    Big p,x,mod;
    //char m[] = "7C55E32520935B3B2C5B193AFD2D1D11";
    char m[33];
    random_hex(m,32);

    p.operator=(m);
    random_hex(m,32);
    x.operator=(m);
    random_hex(m,32);
    mod.operator=(m);
    cout << strlen(m) << " " << mod << endl;
    start = clock();
    T(p,x, mod);
    end = clock();
    msecs = ((double) (end - start)) * 1000 / CLOCKS_PER_SEC;
    cout << "chebyshev time -> " << msecs << endl;

    sha256_test();
    aes_test();

	if (pfc.multi_pairing(2,g2,g1)==1)
		cout << "Signature verifies" << endl;
	else
		cout << "Signature is bad" << endl;

    return 0;
}



