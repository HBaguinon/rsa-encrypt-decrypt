# rsa-encrypt-decrypt
Encrypts user input into ciphertext using RSA algorithm, then decrypts the ciphertext back into the message.

RSA is an asymmetric algorithm which relies on enormous numbers, so BIGNUM objects were used for the program, which was written in C++.

The Prototype.cpp file was written first, using long integers to test the math, before BIGNUM was implemented in the main rsa.cpp file.
