/********************************************************************************************
*										SHA512.cpp 											*
*																							*
*	DESCRIPTION: A SHA2-512 Hash Program.													*
*				 Input Parameters: SHA512 <infile>											*
*																							*
*																							*
*	AUTHOR: Aaron Millikin											START DATE: 4/20/2017	*
*********************************************************************************************/

#include "stdafx.h"
#include <intrin.h>
#include <iostream>
#include <iomanip>
#include <string>
#include <fstream>
#include <algorithm>
#include <cstdio>
#include <ctime>
#include <math.h>

using namespace std;
typedef unsigned long long ull;
ifstream inFile;

// Initial Hash Values
static const ull initHashVals[8]{
	0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
	0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
};

// Round constants
static const ull roundConst[80]{
	0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538,
	0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe,
	0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235,
	0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
	0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab,
	0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
	0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed,
	0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
	0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218,
	0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53,
	0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373,
	0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
	0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c,
	0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6,
	0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc,
	0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
};

//Creates necessary hex bytes to and with buffer that should contain less than 8 bytes
ull getHexfBytes(size_t bytesLeft) {
	ull hexBytes = 0;
	for (size_t i = 0; i < bytesLeft; i++) {
		hexBytes <<= 8;
		hexBytes |= 0xff;
	}
	return hexBytes;
}

//Creates Random Pad Bits
ull getRandBits(int numToPad) {
	ull randBytes = 0;
	srand((unsigned int)time(NULL));
	for (int i = 0; i < numToPad; i++) {
		randBytes <<= 8;
		randBytes |= (rand() % 255);
	};
	return randBytes;
}

//Converts a string to all uppercase characters - ARM
string upCase(string str) {
	transform(str.begin(), str.end(), str.begin(), toupper);
	return str;
}

void prompt()
{
	cout << "Welcome to Aaron's SHA2-512 Hash!" << endl;
	cout << "Accepted input: AES <-action> <key> <mode> <infile> <outfile>" << endl;
}

int main(int argc, char* argv[]) {
	clock_t startTime = clock(), endTime;
	double secondsElapsed;
	string action, mode, keyStr, keyByte;
	streampos begF, endF;
	int bytesLeft = 0, readCnt = 0;
	unsigned int byte, fileSize, readSize;
	ull block;
	streampos begin, end;

	if (argc != 2) {
		cout << "Incorrect number of arguments supplied." << endl;
		prompt();
		return 1;
	}

	inFile.open(argv[2], ios::in | ios::binary);
	if (!inFile) {
		cout << "Can't open input file " << argv[4] << endl;
		prompt();
		return 1;
	}

	//	Determines length of file. - ARM
	begin = inFile.tellg();
	inFile.seekg(0, ios::end);
	end = inFile.tellg();
	fileSize = (end - begin);
	inFile.seekg(0, ios::beg);


	//	Filesize limit of 31 bits. - ARM
	if (fileSize > 2147483647) {
		cout << "File is too large to open. Must be <= 31 bits of data." << endl;
		prompt();
		return 1;
	}

		bytesLeft = fileSize % 16;
		readCnt = fileSize / 16;
	}
	
	};


	// If filesize is less than 8 bytes, only read that amount, padding appropriately before passing through DES.
	// Guaranteed to be encrpytion if this is true because an encrypted file being decrypted would have at least 9 bytes.
	if (fileSize < 16) {
		state = readState(true, bytesLeft);
		if (mode == "CBC") {
			state = xorState(state, iv);
		}
		state = aes(state, action);
	}

	// Read file for duration of count determined earlier (amount of full 128-bit blocks available)
	// pass through AES, write to outFile.
	while (readCnt > 0) {
		readCnt--;
		state = readState(false);

		//If CBC and Encrypting, XOR block with iv
		//If CBC and Decrypting, save ciphertext block for next iv in tempIV
		if (mode == "CBC" && action == "E") {
			state = xorState(state, iv);
		}
		else if (mode == "CBC" && action == "D") {
			tempIV = state;
		}
		state = aes(state, action);

		//If CBC and Encrypting, set next iv to ciphertext state
		//If CBC and Decrypting, XOR state with iv, set next iv from tempIV
		if (mode == "CBC" && action == "D") {
			state = xorState(state, iv);
			iv = tempIV;
		}
		else if (mode == "CBC" && action == "E") {
			iv = state;
		}
		writeState(state, false);
	};

	// Read remaining bytes. If encrypting, we append random bits during read to provide a ensure 128-bit state
	// Write result. If decrypting, only write the correct amount of bytes left, not the extra padding.
	if (bytesLeft > 0) {
		if (action == "E") {
			state = readState(true, bytesLeft);
			if (mode == "CBC") {
				state = xorState(state, iv);
			}
			state = aes(state, action);
			writeState(state, false);
		}
		else if (action == "D") {
			state = readState(false);
			state = aes(state, action);
			if (mode == "CBC") {
				state = xorState(state, iv);
			}
			writeState(state, true, (16 - bytesLeft));
		}
	}

	endTime = clock();
	secondsElapsed = double(endTime - startTime) / CLOCKS_PER_SEC;
	cout << fixed << setprecision(3);
	cout << secondsElapsed << " Seconds Elapsed." << endl;

	return 0;
}