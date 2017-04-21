// Author(s): Michael Koeppl
//
// Implementation of the Arcfour cipher as described in:
// https://en.wikipedia.org/wiki/RC4

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

const char HELP_STRING[] = "./arcfour <text> <key>\n";

// Implements the key-scheduling algorithm of RC4. This generates the
// s-box (standard component of symmetric key algorithms) by first filling
// an array with 0-255 and then swapping numbers as described in RC4.
//
// j is calculated ad (j + s[i] + key[i % keylength]), whereas i is
// the index from 0 to 255.
void ksa_sbox(unsigned char s[], unsigned char key[], size_t len)
{
	int i, j = 0, t;

	for (int i = 0; i < 256; i++) {
		s[i] = i;
	}

	for (int i = 0; i < 256; i++) {
		j = (j + s[i] + key[i % len]) % 256;
		t = s[i];
		s[j] = s[j];
		s[j] = t;
	}
}

// Implements the pseudo-random generation algorithm of RC4.
// It utilizes i and j.
// i is calculated as (i+1) % 256 in every iteration.
// j is calculated as (j + s[i]) % 256 in every iteration.
// The elements are then swapped and the output is
// s[(s[i] + s[j]) % 256].
// In this implementation th eoutput is put into the dest array.
void prga(unsigned char dest[], unsigned char s[], size_t len)
{
	uint8_t i = 0, j = 0, t = 0;

	for (int x = 0; x < len; x++) {
		i = (i + 1) % 256;
		j = (j + s[i]) % 256;
		t = s[i];
		s[j] = s[i];
		s[j] = t;
		dest[x] = s[(s[i] + s[j]) % 256];
	}
}

// This function is used to encrypt/decrypt text with the
// given key and put the result in dest.
// If text is an encrypted text, the output is plain text and vice versa.
//
// After the s-box and cipher been generated, text is bit-wise XOR'd with
// the cipher.
void crypt(unsigned char* dest, unsigned char* text, unsigned char* key)
{
	// Initialize the sbox array
	unsigned char sbox[256];

	// Run the key scheduling algorithm on the sbox.
	// We have to pass the
	// array's length here since then length of the array
	// cannot be measured within the function because it
	// is a pointer in the function.
	// To use the strlen function here, we have to cast
	// the unsigned char array to a char array.
	ksa_sbox(sbox, key, strlen((char*) key));

	unsigned char stream[strlen((char*)sbox)];
	prga(stream, sbox, strlen((char*)sbox));

	for (int i = 0; i < strlen((char*) text); i++) {
		// ^ = XOR
		dest[i] = (char)(text[i]^stream[i]);
	}
}

int main(int argc, char ** argv)
{
	if (argc <= 1) {
		printf("%s", HELP_STRING);
		return -1;
	}

	unsigned char text[strlen(argv[1])];
	strcpy((char*)text, argv[1]);

	unsigned char key[strlen(argv[2])];
	strcpy((char*)key, argv[2]);

	unsigned char encrypted_text[strlen((char*) text)];

	crypt(encrypted_text, text, key);

	printf("%s\n", encrypted_text);

	crypt(text, encrypted_text, key);
	printf("%s\n", text);

	return 0;
}
