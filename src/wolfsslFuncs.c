/* wolfsslFuncs.c
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

#include "include/wolfssl.h"

#define SALT_SIZE       8
#define DES3_BLOCK_SIZE 24

 /* type casting to integers for comparison */
#define LENGTH_IN       (int)strlen(in)
#define SZALGS1         (int) sizeof(algsenc)
#define SZALGS2         (int) sizeof(algsother)
#define SZFRST1         (int) sizeof(algsenc[0])
#define SZFRST2         (int) sizeof(algsother[0])
/*end type casting */

#ifdef HAVE_BLAKE2
    #define BLAKE_DIGEST_SIZE 64
#endif /* HAVE_BLAKE2 */

int     loop       =   1;       /* benchmarking loop */
int     i          =   0;       /* loop variable */
int64_t blocks;                 /* blocks used during benchmarking */

/* 
 * generic help function
 */
 void wolfsslHelp()
 {  printf("*************************************************************\n");
    printf("-help           Help, print out this help menu\n");
    printf("*************************************************************\n");
    printf("Only set one of the following.\n\n");
    printf("-e              Encrypt a file or some user input\n");
    printf("-d              Decrypt an encrypted file\n");
    printf("-h              Hash a file or input\n");
    printf("-b              Benchmark one of the algorithms\n");
    printf("*************************************************************\n");
    /*optional flags*/
    printf("Optional Flags.\n\n");
    printf("-i              input file to manage\n");
    printf("-o              file to output as a result of option\n");
    printf("-p              user custom password\n");
    printf("-V              user custom IV (hex input only)\n");
    printf("-K              user custom key(hex input only)\n");
    printf("-x              when using -V and -k this will print result of\n"
           "                encryption for user verification.\n"
           "                This flag takes no arguments.\n");
    printf("-l              used by Hash, set length of string to hash.\n");
    printf("-t              used by Benchmark, set time in seconds to run.\n");
    printf("-v              display a more verbose help menu\n");
    printf("*************************************************************\n");
        /* encryption/decryption help lists options */
    printf("\nUSAGE: wolfssl [-e | -d] <-algorithm> <-i filename> \n"
           "EXAMPLE: \n\nwolfssl -e aes-cbc-128 -p Thi$i$myPa$$w0rd"
           "-i somefile.txt -o encryptedfile.txt\n\n");
 }

/*
 * verbose help function
 */ 
void wolfsslVerboseHelp()
{
    const char* algsenc[] = {        /* list of acceptable algorithms */
#ifndef NO_MD5
            "-md5"
#endif
#ifndef NO_SHA
                ,"-sha"
#endif
#ifndef NO_SHA256
                ,"-sha256"
#endif
#ifdef CYASSL_SHA384
                ,"-sha384"
#endif
#ifdef CYASSL_SHA512
                ,"-sha512"
#endif
#ifdef HAVE_BLAKE2
                ,"-blake2b"
#endif
        };

    /* benchmark options */
    const char* algsother[] = {      /* list of acceptable algorithms */
#ifndef NO_AES
            "-aes-cbc"
#endif
#ifdef CYASSL_AES_COUNTER
                , "-aes-ctr"
#endif
#ifndef NO_DES3
                , "-3des"
#endif
#ifdef HAVE_CAMELLIA
                , "-camellia"
#endif
#ifndef NO_MD5
                , "-md5"
#endif
#ifndef NO_SHA
                , "-sha"
#endif
#ifndef NO_SHA256
                , "-sha256"
#endif
#ifdef CYASSL_SHA384
                , "-sha384"
#endif
#ifdef CYASSL_SHA512
                , "-sha512"
#endif
#ifdef HAVE_BLAKE2
                , "-blake2b"
#endif
        };
        printf("\nwolfssl Command Line Utility version 0.1\n\n");
        printf("Available En/De crypt Algorithms with current configure settings.\n");
#ifndef NO_AES
        printf("-aes-cbc-128\t\t-aes-cbc-192\t\t-aes-cbc-256\n");
#endif
#ifdef CYASSL_AES_COUNTER
        printf("-aes-ctr-128\t\t-aes-ctr-192\t\t-aes-ctr-256\n");
#endif
#ifndef NO_DES3
        printf("-3des-cbc-56\t\t-3des-cbc-112\t\t-3des-cbc-168\n");
#endif
#ifdef HAVE_CAMELLIA
        printf("-camellia-cbc-128\t-camellia-cbc-192\t"
                "-camellia-cbc-256\n");
#endif
    printf("\nUsage: wolfssl -h [-l length] [-alg]");
    printf("\nAvailable algorithms with current configure settings:\n");
    for (i = 0; i < SZALGS1/SZFRST1; i++) {
            printf("%s\n", algsenc[i]);
    }
    printf("\nUsage: wolfssl -b [-t timer(1-10)] [-alg]");
    printf("\nAvailable tests: (-all to test all)\n");
    printf("Available tests with current configure settings:\n");
    for(i = 0; i < SZALGS2/SZFRST2; i++) {
        printf("%s\n", algsother[i]);
    }
    printf("\n");
}

/*
 * finds algorithm for encryption/decryption
 */
int wolfsslGetAlgo(char* name, char** alg, char** mode, int* size)
{
    int     ret         = 0;        /* return variable */
    int     nameCheck   = 0;        /* check for acceptable name */
    int     modeCheck   = 0;        /* check for acceptable mode */
    char*   sz          = 0;        /* key size provided */
    const char* acceptAlgs[]  = {   /* list of acceptable algorithms */
#ifndef NO_AES
        "aes"
#endif
#ifndef NO_DES3
            , "3des"
#endif
#ifdef HAVE_CAMELLIA
            , "camellia"
#endif
    };
    const char* acceptMode[] = {"cbc"
#ifdef CYASSL_AES_COUNTER
        , "ctr"
#endif
    };

    /* gets name after first '-' and before the second */
    *alg = strtok(name, "-");
    for (i = 0; i < (int)(sizeof(acceptAlgs)/sizeof(acceptAlgs[0])); i++) {
        if (strcmp(*alg, acceptAlgs[i]) == 0 )
            nameCheck = 1;
    }
    /* gets mode after second "-" and before the third */
    if (nameCheck != 0) {
        *mode = strtok(NULL, "-");
        for (i = 0; i < (int) (sizeof(acceptMode)/sizeof(acceptMode[0])); i++) {
            if (strcmp(*mode, acceptMode[i]) == 0)
                modeCheck = 1;
        }
    }
    /* if name or mode doesn't match acceptable options */
    if (nameCheck == 0 || modeCheck == 0) {
        printf("Invalid entry\n");
        return FATAL_ERROR;
    }

    /* gets size after third "-" */
    sz = strtok(NULL, "-");
    *size = atoi(sz);

    /* checks key sizes for acceptability */
#ifndef NO_AES
    if (strcmp(*alg, "aes") == 0) {
        ret = AES_BLOCK_SIZE;
        if (*size != 128 && *size != 192 && *size != 256) {
            printf("Invalid AES pwdKey size. Should be: %d\n", ret);
            ret = FATAL_ERROR;
        }
    }
#endif
#ifndef NO_DES3
    else if (strcmp(*alg, "3des") == 0) {
        ret = DES3_BLOCK_SIZE;
        if (*size != 56 && *size != 112 && *size != 168) {
            printf("Invalid 3DES pwdKey size\n");
            ret = FATAL_ERROR;
        }
    }
#endif
#ifdef HAVE_CAMELLIA
    else if (strcmp(*alg, "camellia") == 0) {
        ret = CAMELLIA_BLOCK_SIZE;
        if (*size != 128 && *size != 192 && *size != 256) {
            printf("Invalid Camellia pwdKey size\n");
            ret = FATAL_ERROR;
        }
    }
#endif

    else {
        printf("Invalid algorithm: %s\n", *alg);
        ret = FATAL_ERROR;
    }
    return ret;
}

/*
 * makes a cyptographically secure key by stretching a user entered pwdKey
 */
int wolfsslGenKey(RNG* rng, byte* pwdKey, int size, byte* salt, int pad)
{
    int ret;        /* return variable */

    /* randomly generates salt */

    ret = RNG_GenerateBlock(rng, salt, SALT_SIZE-1);

    if (ret != 0)
        return ret;

    /* set first value of salt to let us know
     * if message has padding or not 
     */
    if (pad == 0)
        salt[0] = 0;

    /* stretches pwdKey */
    ret = (int) PBKDF2(pwdKey, pwdKey, strlen((const char*)pwdKey), salt, SALT_SIZE, 
                                                            4096, size, SHA256);
    if (ret != 0)
        return ret;

    return 0;
}

/*
 * secure data entry by turning off key echoing in the terminal
 */
int wolfsslNoEcho(char* pwdKey, int size)
{
    struct termios oflags, nflags;
    char* success;
    int ret;

    /* disabling echo */
    tcgetattr(fileno(stdin), &oflags);
    nflags = oflags;
    nflags.c_lflag &= ~ECHO;
    nflags.c_lflag |= ECHONL;

    if (tcsetattr(fileno(stdin), TCSANOW, &nflags) != 0) {
        printf("Error\n");
        return FATAL_ERROR;
    }

    printf("pwdKey: ");
    success = fgets(pwdKey, size, stdin);
    if (success == NULL) {
        /* User wants manual input to be encrypted
         * Do Nothing 
         */
    }

    pwdKey[strlen(pwdKey) - 1] = 0;
    
    /* restore terminal */
    ret = tcsetattr(fileno(stdin), TCSANOW, &oflags);
    if (ret != 0) {
        printf("Error\n");
        return FATAL_ERROR;
    }
    return 0;
}

/*
 * adds character to end of string 
 */
void wolfsslAppend(char* s, char c)
{
    int len = (int) strlen(s); /* length of string*/

    s[len] = c;
    s[len+1] = '\0';
}

/*
 * resets benchmarking loop
 */
void wolfsslStop(int signo)
{
    (void) signo; /* type cast to void for unused variable */
    loop = 0;
}

/*
 * gets current time durring program execution
 */
double wolfsslGetTime(void)
{
    struct timeval tv;

    gettimeofday(&tv, 0);

    return (double)tv.tv_sec + (double)tv.tv_usec / 1000000;
}

/* 
 * prints out stats for benchmarking
 */
void wolfsslStats(double start, int blockSize)
{
    int64_t compBlocks = blocks;
    double total = wolfsslGetTime() - start, mbs;

    printf("took%6.3f seconds, blocks = %llu\n", total,
            (unsigned long long)compBlocks);

    mbs = compBlocks * blockSize / MEGABYTE / total;
    printf("Average MB/s = %8.1f\n", mbs);
}
