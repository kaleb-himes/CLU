/* util.h
 *
 * Copyright (C) 2006-2014 wolfSSL Inc.
 * This file is part of CyaSSL.
 *
 * CyaSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * CyaSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,USA
 */

#include <string.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <termios.h>
#include <sys/time.h>

/* cyassl includes */
#include <cyassl/options.h>
#include <cyassl/ctaocrypt/random.h>
#include <cyassl/ctaocrypt/pwdbased.h>
#include <cyassl/ctaocrypt/aes.h>
#include <cyassl/ctaocrypt/des3.h>
#include <cyassl/ctaocrypt/error-crypt.h>
#include <cyassl/error-ssl.h>

#ifndef NO_MD5
    #include <cyassl/ctaocrypt/md5.h>
#endif

#ifndef NO_SHA
    #include <cyassl/ctaocrypt/sha.h>
#endif

#ifndef NO_SHA256
    #include <cyassl/ctaocrypt/sha256.h>
#endif

#ifdef CYASSL_SHA512
    #include <cyassl/ctaocrypt/sha512.h>
#endif

#ifdef HAVE_BLAKE2
    #include <cyassl/ctaocrypt/blake2.h>
#endif

#ifdef HAVE_CAMELLIA
    #include <cyassl/ctaocrypt/camellia.h>
#endif

#ifndef UTIL_H_INCLUDED
	#define UTIL_H_INCLUDED

#define BLOCK_SIZE 16384
#define MEGABYTE (1024*1024)
#define MAX_THREADS 64

/* A general help of wolfsslMain */
void help(void);

/* encryption argument function */
int wolfsslSetup(int argc, char** argv, char action);

/* hash argument function */
int wolfsslHashSetup(int argc, char** argv);

/* benchmark argument function */
int wolfsslBenchSetup(int argc, char** argv);

/* help function */
void wolfsslHelp(const char* name);

/* find algorithm for encryption/decryption */
int wolfsslGetAlgo(char* name, char** alg, char** mode, int* size);

/* generates key based on password provided */
int wolfsslGenKey(RNG* rng, byte* pwdKey, int size, byte* salt, int pad);

/* secure entry of password */
int wolfsslNoEcho(char* pwdKey, int size);

/* adds characters to end of string */
void wolfsslAppend(char* s, char c);

/* interrupt function*/
void wolfsslStop(int signo);

/* finds current time during runtime */
double wolfsslGetTime(void);

/* A function to convert from Hex to Binary */
int wolfsslHexToBin(const char* h1, byte** b1, word32* b1Sz,
                    const char* h2, byte** b2, word32* b2Sz,
                    const char* h3, byte** b3, word32* b3Sz,
                    const char* h4, byte** b4, word32* b4Sz);

/* A function to free malloced byte* buffers after conversion*/
void wolfsslFreeBins(byte* b1, byte* b2, byte* b3, byte* b4, byte* b5);

/* function to display stats results from benchmark */
void wolfsslStats(double start, int blockSize);

/* encryption function */
int wolfsslEncrypt(char* alg, char* mode, byte* pwdKey, byte* key, int size, 
								char* in, char* out, byte* iv, int block, 
                                int ivCheck);

/* decryption function */
int wolfsslDecrypt(char* alg, char* mode, byte* pwdKey, byte* key, int size, 
						char* in, char* out, byte* iv, int block, int keyType);

/* benchmarking function */
int wolfsslBenchmark(int timer, int* option);

/* hashing function */
int wolfsslHash(char* in, char* len, char* out, char* alg, int size);
#endif

