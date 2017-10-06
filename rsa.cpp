/*******************************************************************************
* NAME: HAROLD DANE C. BAGUINON                                                *
* DATE: 05/03/2016                                                             *
* DATE DUE: 05/05/2016 11:59:00 PM                                             *
* COURSE: CSC555 010                                                           *
* PROFESSOR: DR. ZHANG                                                         *
* PROJECT: #5                                                                  *
* FILENAME: rsa.cpp                                                            *
* PURPOSE: This program is the fith and final project. The purpose of the      *
*          project is to study the RSA encryption and decryption algorithms by *
*          encrypting and decrypting user input while showing each step in the *
*          process along the way, such as generating p, q, common modulus, and *
*          both public and private keys.                                       *
*******************************************************************************/

#include <iostream>				// for i/o functions
#include <fstream>				// for external file streams
#include <cstdlib>				// for EXIT_FAILURE
#include <string>				// for string objects
#include <cstring>				// for cstring objects
#include <bitset>               // for bitset
#include <sstream>              // for stringstream
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <cmath>

using namespace std;

// Functions used ... 
/*******************************************************************************
* Normally, we would use functions to separate the various parts of the program*
* such as p & q generation, key generation, encryption, and decryption. But due*
* to the use of BIGNUM objects and their respective pointers, the programmer   *
* was unable to write the functions as desired. Thus, the programmer had to    *
* settle for writting all of the code within the main() function, which is     *
* normally undesireable.                                                       *
*******************************************************************************/

int main() {
    BN_CTX *ctx; //memory space
    ctx = BN_CTX_new();
    if(!ctx) /* Handle error */
    {
        exit (EXIT_FAILURE);
    }
    BIGNUM *p;
    BIGNUM *q;
    BIGNUM *n;
    BIGNUM *p1;
    BIGNUM *q1;
    BIGNUM *tot; //totient
    BIGNUM *e;
    BIGNUM *quot; //quotient
    BIGNUM *x;
    BIGNUM *y;
    BIGNUM *r;
    BIGNUM *lastX;
    BIGNUM *lastY;
    BIGNUM *lastR;
    BIGNUM *tmp;
    BIGNUM *quotX;
    BIGNUM *quotY;
    BIGNUM *d;
    BIGNUM *c;
    BIGNUM *m;
    BIGNUM *me;
    BIGNUM *cd;
    string messagestring;
    int message;
    //BIGNUM **messageBN;
    
    p = BN_new();
	q = BN_new();
    n = BN_new();
    p1 = BN_new();
	q1 = BN_new();
    tot = BN_new();
    e = BN_new();
    quot = BN_new();
    x = BN_new();
    y = BN_new();
    r = BN_new();
    lastX = BN_new();
    lastY = BN_new();
    lastR = BN_new();
    tmp = BN_new();
    quotX = BN_new();
    quotY = BN_new();
    d = BN_new();
    c = BN_new();
    cd = BN_new();
    me = BN_new();
    m = BN_new();
    //messageBN = BN_new();
    //*messageBN = BN_new();
    
    BN_generate_prime_ex(p, 1024, 0, NULL, NULL, NULL);
    BN_generate_prime_ex(q, 1024, 0, NULL, NULL, NULL);
        
    BN_mul_word(p1, 0);
    BN_add(p1, p, p1);
    BN_mul_word(q1, 0);
    BN_add(q1, q, q1);
    BN_sub_word(p1, 1);
    BN_sub_word(q1, 1);
        
    BN_mul(n, p, q, ctx);
    BN_mul(tot, p1, q1, ctx);
    
	BN_mul_word(e, 0);
    BN_add_word(e, 65537);
    
    /*for testing, set p, q, e
    BN_mul_word(p, 0);
    BN_add_word(p, 47);
    BN_mul_word(q, 0);
    BN_add_word(q, 53);
    BN_mul(n, p, q, ctx);
    BN_add(p1, p, p1);
    BN_add(q1, q, q1);
    //p1 = p;
    //q1 = q;
    BN_sub_word(p1, 1);
    BN_sub_word(q1, 1);
    BN_mul(tot, p1, q1, ctx);
    BN_mul_word(e, 0);
    BN_add_word(e, 17);
    end test variables*/
    
    BN_add_word(x, 0);
    BN_add_word(y, 1);
    BN_add(r, tot, r);
    //r = tot;
    BN_add_word(lastX, 1);
    BN_add_word(lastY, 0);
    BN_add(lastR, e, lastR);
    //lastR = e;
    cout << "p: " << BN_bn2dec(p) << endl << endl;
    cout << "q: " << BN_bn2dec(q) << endl << endl;
    cout << "n: " << BN_bn2dec(n) << endl << endl;
    cout << "p1: " << BN_bn2dec(p1) << endl << endl;
    cout << "q1: " << BN_bn2dec(q1) << endl << endl;
    cout << "tot: " << BN_bn2dec(tot) << endl << endl;
    cout << "Public Key e: " << BN_bn2dec(e) << endl << endl;
    
    while (BN_is_zero(r)==0) {
        BN_div(quot, NULL, lastR, r, ctx);
        //quot = e / r;
        
        BN_mod(tmp, lastR, r, ctx);
        //tmp = e % r;
        BN_mul_word(lastR, 0);
        BN_add(lastR, r, lastR);
        //lastR = r;
        BN_mul_word(r, 0);
        BN_add(r, tmp, r);
        //r = tmp;
        
        BN_mul(quotX, quot, x, ctx);
        BN_sub(tmp, lastX, quotX);
        //tmp = lastX - quot * x;
        BN_mul_word(lastX, 0);
        BN_add(lastX, x, lastX);
        //lastX = x;
        BN_mul_word(x, 0);
        BN_add(x, tmp, x);
        //x = tmp;
        
        BN_mul(quotY, quot, y, ctx);
        BN_sub(tmp, lastY, quotY);
        //tmp = lastY - quot * y;
        BN_mul_word(lastY, 0);
        BN_add(lastY, y, lastY);
        //lastY = y;
        BN_mul_word(y, 0);
        BN_add(y, tmp, y);
        //y = tmp;
        }
    BN_mul_word(d, 0);
    BN_add(d, lastX, d);
    if (BN_cmp(d, m) == -1) {
        BN_add(d, tot, d);
    }
    //d = x;
    
	cout << "Private Key d: " << BN_bn2dec(d) << endl << endl;
        
    cout << "Enter a message: ";
    
    getline(cin, messagestring);
    char *textArray = new char [256];
    strcpy(textArray, messagestring.c_str());
    
    /*
    getline(cin, messagestring);
    int messagestringSize = messagestring.size();
    char *textArray = new char [messagestring.size()];
    memcpy(textArray, messagestring.c_str(), messagestringSize);
    */
    
    //messageBN = BN_new();
    
    //BN_dec2bn(messageBN, textArray);
    
    message = atoi(messagestring.c_str());
    cout << "Message: " << message << endl << endl;
    
    //cout << "messageBN: " << BN_bn2dec(*messageBN) << endl << endl;
    BN_add_word(m, message);
    //cout << "post convert m: " << BN_bn2dec(m) << endl << endl;
    //BN_exp(me, m, e, ctx);
    //BN_mod(c, me, n, ctx);
    BN_mod_exp(c, m, e, n, ctx);
    
    cout << "Cyphertext: " << BN_bn2dec(c) << endl << endl;
    
    //BN_exp(cd, c, d, ctx);
    //BN_mod(m, cd, n, ctx);
    BN_mod_exp(m, c, d, n, ctx);
    
    cout << "Decrypted message: " << BN_bn2dec(m) << endl << endl;
    
    BN_CTX_free(ctx);
    return 0;
}
