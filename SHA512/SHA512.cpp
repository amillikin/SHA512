/********************************************************************************************
*										SHA512.cpp 											*
*																							*
*	DESCRIPTION: A SHA-512 Hash Program.													*
*				 Takes a file and produces the respective SHA-512 Hash Value.				*
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

struct hashStruct {
	ull messageBlock[16];
	ull w[80];
	ull a;
	ull b;
	ull c;
	ull d;
	ull e;
	ull f;
	ull g;
	ull h;
	ull mixer1;
	ull mixer2;
};

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

// Creates necessary hex bytes to and with buffer that should contain less than 8 bytes
ull getMask(size_t maskAmt) {
	ull mask = 0;
	for (size_t i = 0; i < maskAmt; i++) {
		mask <<= 8;
		mask |= 0xff;
	}
	return mask;
}

// Right Rotate
ull rr(ull rotWord, int rotAmt) {
	return ((rotWord & getMask(rotAmt)) << rotAmt) || (rotWord >> rotAmt);
}

// Right Shift
ull rs(ull shiftWord, int shiftAmt) {
	return shiftWord >> shiftAmt;
}

// Majority
ull maj(ull a, ull b, ull c) {
	return (a & b) ^ (a & c) ^ (b & c);
}

// Conditional
ull cond(ull e, ull f, ull g) {
	return (e & f) ^ (~e & g);
}

// Rotates A for use in determining mixer1
ull rotA(ull a) {
	return rr(a, 28) ^ rr(a, 34) ^ rr(a, 39);
}

// Rotate E for use in determining mixer2
ull rotE(ull e) {
	return rr(e, 14) ^ rr(e, 18) ^ rr(e, 41);
}

// Copies message block into word array, 
// then fills the remainder of the array with the calculated value
hashStruct fillWordArray(hashStruct block) {
	for (int i = 0; i < 16; i++) {
		block.w[i] = _byteswap_uint64(block.messageBlock[i]);
	}
	for (int i = 16; i < 80; i++) {
		block.w[i] = block.w[i - 16] + (rr(block.w[i - 15], 1) ^ rr(block.w[i - 15], 8) ^ rs(block.w[i - 15], 7))
			+ block.w[i - 7] + (rr(block.w[i - 2], 19) ^ rr(block.w[i - 2], 61) ^ rs(block.w[i - 2], 6));
	}
	return block;
}

// Organizes the hash steps that take place each of the 80 rounds
hashStruct hashCompression(hashStruct block) {
	block = fillWordArray(block);

	for (int i = 0; i < 80; i++) {
		block.mixer1 = maj(block.a, block.b, block.c) + rotA(block.a);
		block.mixer2 = block.h + cond(block.e, block.f, block.g) + rotE(block.e)
					+ block.w[i] + roundConst[i];
		block.h = block.g;
		block.g = block.f;
		block.f = block.e;
		block.e = block.d + block.mixer2;
		block.d = block.c;
		block.c = block.b;
		block.b = block.a;
		block.a = block.mixer1 + block.mixer2;
	}
	return block;
}

//Writes a state to the outfile
void writeHash(hashStruct block) {
	cout << hex;
	cout << block.a << " ";
	cout << block.b << " ";
	cout << block.c << " ";
	cout << block.d << " ";
	cout << block.e << " ";
	cout << block.f << " ";
	cout << block.g << " ";
	cout << block.h << " ";
}

// Read remaining bytes and pad accordingly.
// If no remaining bytes, final messageBlock sets first bit to 1, 
// followed by all 0s until the last word which is the filesize
hashStruct padBlock(hashStruct block, ull fileSize, int bytesLeft) {
	if (bytesLeft > 0) {
		// File will contain only full bytes, so we need at least 8 bytes for file length
		// and then 1 byte for appending 0x80.
		// If there are left over bytes, but less than the 9 required,
		// We will pad this last message block with 0x80 and 0x0 until full 128 bytes
		// Then create one final block of 0x0 and the final word being the file length
		// Else we can just append 0x80 where the file ends, 
		// set the last word to file length, and fill between with 0x0
		inFile.read(reinterpret_cast<char*>(&block.messageBlock), sizeof(block.messageBlock)-bytesLeft);
		int padStart = ((128 - bytesLeft) / 16);
		int shiftAmt = ((128 - bytesLeft) % 16);

		if (bytesLeft < 9) {
			block.messageBlock[padStart] ^= (0x80 << (shiftAmt - 1));
			for (int i = (padStart + 1); i < 16; i++) {
				block.messageBlock[i] = 0x0;
			}
			block = hashCompression(block);

			for (int i = 0; i < 15; i++) {
				block.messageBlock[i] = 0x0;
			}
			block.messageBlock[15] = fileSize;
			block = hashCompression(block);
		}
		else {
			block.messageBlock[padStart] ^= (0x80 << (shiftAmt - 1));
			for (int i = (padStart + 1); i < 15; i++) {
				block.messageBlock[i] = 0x0;
			}
			block.messageBlock[15] = fileSize;
			block = hashCompression(block);
		}
	}
	else {
		block.messageBlock[0] = 0x8000000000000000;
		for (int i = 1; i < 15; i++) {
			block.messageBlock[i] = 0x0;
		}
		block.messageBlock[15] = fileSize;
		block = hashCompression(block);
	}
	return block;
}

void prompt()
{
	cout << "Welcome to Aaron's SHA-512 Hash!" << endl;
	cout << "Accepted input: SHA512 <infile>" << endl;
}

int main(int argc, char* argv[]) {
	clock_t startTime = clock(), endTime;
	double secondsElapsed;
	streampos begF, endF;
	int bytesLeft = 0;
	ull fileSize = 0, readSize = 0, readCnt = 0;
	hashStruct block;
	streampos begin, end;

	if (argc != 2) {
		cout << "Incorrect number of arguments supplied." << endl;
		prompt();
		return 1;
	}

	inFile.open(argv[1], ios::in | ios::binary);
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

	bytesLeft = (fileSize % 128) ;
	readCnt = fileSize / 128;

	// Sets initial hash digest values
	block.a = initHashVals[0];
	block.b = initHashVals[1];
	block.c = initHashVals[2];
	block.d = initHashVals[3];
	block.e = initHashVals[4];
	block.f = initHashVals[5];
	block.g = initHashVals[6];
	block.h = initHashVals[7];

	// Read file for duration of count determined earlier (amount of full 128-bit blocks available)
	// pass through AES, write to outFile.
	while (readCnt > 0) {
		readCnt--;
		inFile.read(reinterpret_cast<char*>(&block.messageBlock), sizeof(block.messageBlock));
		block = hashCompression(block);
	}
	
	// Handles the final padding
	block = padBlock(block, fileSize, bytesLeft);
	
	// Writes the hash value to the console
	writeHash(block);
	
	endTime = clock();
	secondsElapsed = double(endTime - startTime) / CLOCKS_PER_SEC;
	cout << fixed << setprecision(3);
	cout << "Elapsed Time: " << secondsElapsed << endl;

	return 0;
}