/* util.c
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
#define MAX             1024
#define LENGTH_IN       (int)strlen(in)      /* type cast unsigned int to int */
#define SZALGS          (int) sizeof(algs)   /* type cast unsigned int to int */
#define SZFRST          (int) sizeof(algs[0])/* type cast unsigned int to int */

#ifdef HAVE_BLAKE2

#define BLAKE_DIGEST_SIZE 64

#endif /* HAVE_BLAKE2 */

int     loop       =   1;       /* benchmarking loop */
int     i          =   0;       /* loop variable */
int64_t blocks;                 /* blocks used during benchmarking */

/*
 * hash argument function
 */
int wolfsslHashSetup(int argc, char** argv)
{
    int     ret  =   0;         /* return variable, counter */
    char*   in;                 /* input variable */
    char*   out     =   NULL;   /* output variable */
    const char* algs[]  =   {   /* list of acceptable algorithms */
#ifndef NO_MD5
        "-md5"
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

    char*   alg;                /* algorithm being used */
    int     algCheck=   0;      /* acceptable algorithm check */
    int     inCheck =   0;      /* input check */
    int     size    =   0;      /* message digest size */           
    char*   len     =   NULL;   /* length to be hashed */

#ifdef HAVE_BLAKE2
    size = BLAKE_DIGEST_SIZE;
#endif

    /* help checking */
    if (argc == 2) {
        wolfsslHelp("-h");
        return 0;
    }
    for (i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-help") == 0) {
            wolfsslHelp("-h");
            return 0;
        }
    }

    for (i = 0; i < SZALGS/SZFRST; i++) {
        /* checks for acceptable algorithms */
        if (strcmp(argv[2], algs[i]) == 0) {
            alg = argv[2];
            algCheck = 1;
        }
    }
    if (algCheck == 0) {
        printf("Invalid algorithm\n");
        return FATAL_ERROR;
    }

    for (i = 3; i < argc; i++) {
        if (strcmp(argv[i], "-i") == 0 && argv[i+1] != NULL) {
            /* input file/text */
            in = malloc(strlen(argv[i+1])+1);
            strcpy(in, &argv[i+1][0]);
            in[strlen(argv[i+1])] = '\0';
            inCheck = 1;
            i++;
        }
        else if (strcmp(argv[i], "-o") == 0 && argv[i+1] != NULL) {
            /* output file */
            out = argv[i+1];
            i++;
        }
        else if (strcmp(argv[i], "-s") == 0 && argv[i+1] != NULL) {
            /* size of output */
#ifndef HAVE_BLAKE2
            printf("Sorry, only to be used with Blake2b enabled\n");
#else
            size = atoi(argv[i+1]);
            if (size <= 0 || size > 64) {
                printf("Invalid size, Must be between 1-64. Using default.\n");
                size = BLAKE_DIGEST_SIZE;
            }
#endif
            i++;
        }
        else if (strcmp(argv[i], "-l") == 0 && argv[i+1] != NULL) {
            /* length of string to hash */
            len = malloc(strlen(argv[i+1])+1);
            strcpy(len, &argv[i+1][0]);
            len[strlen(argv[i+1])] = '\0';
            i++;
        } 
        else {
            printf("Unknown argument %s. Ignoring\n", argv[i]);
        }
    }
    if (inCheck == 0) {
        printf("Must have input as either a file or standard I/O\n");
        free(len);
        return FATAL_ERROR;
    }
    /* sets default size of algorithm */
#ifndef NO_MD5
    if (strcmp(alg, "-md5") == 0) 
        size = MD5_DIGEST_SIZE;
#endif

#ifndef NO_SHA
    if (strcmp(alg, "-sha") == 0) 
        size = SHA_DIGEST_SIZE;
#endif

#ifndef NO_SHA256
    if (strcmp(alg, "-sha256") == 0) 
        size = SHA256_DIGEST_SIZE;
#endif

#ifdef CYASSL_SHA384
    if (strcmp(alg, "-sha384") == 0)
        size = SHA384_DIGEST_SIZE;
#endif

#ifdef CYASSL_SHA512
    if (strcmp(alg, "-sha512") == 0)
        size = SHA512_DIGEST_SIZE;
#endif

    /* hashing function */
    wolfsslHash(in, len, out, alg, size);

    free(in);
    free(len);

    return ret;
}

/*
 * help function
 */ 
void wolfsslHelp(const char* name)
{
    if (strcmp(name, "-h") == 0) {    /* hash help prints hash options */
        const char* algs[] = {        /* list of acceptable algorithms */
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

        printf("\nUSAGE: cyassl hash <-algorithm> <-i filename> [-o filename]"
                " [-s size]\n");
        printf("\n( NOTE: *size use for Blake2b range: 1-64)\n");
        printf("Available algorithms with current configure settings:\n\n");
        for (i = 0; i < SZALGS/SZFRST; i++) {
            printf("%s\n", algs[i]);
        }
        printf("\n");
    }
    /* benchmark help lists benchmark options */
    else if (strcmp(name, "-b") == 0) { 
        const char* algs[] = {      /* list of acceptable algorithms */
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
        printf("\nUsage: cyassl benchmark [-t timer(1-10)] [-alg]\n");
        printf("\nAvailable tests: (-all to test all)\n");
        printf("Available tests with current configure settings:\n\n");
        for(i = 0; i < SZALGS/SZFRST; i++) {
            printf("%s\n", algs[i]);
        }
        printf("\n");
    }
    else {
        /* encryption/decryption help lists options */
        printf("\nUSAGE: wolfssl %s <-algorithm> <-i filename> ", name);
        printf("[-o filename] [-k password] [-iv IV]\n\n"
                "Available Algorithms with current configure settings.\n\n");
#ifndef NO_AES
        printf("\n-aes-cbc-128\t\t-aes-cbc-192\t\t-aes-cbc-256\n");
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
        printf("\n");
    }
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
            printf("Invalid AES pwdKey size\n");
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

    if (pad == 0)        /* sets first value of salt to check if the */
        salt[0] = 0;            /* message is padded */

    /* stretches pwdKey */
    ret = PBKDF2(pwdKey, pwdKey, strlen((const char*)pwdKey), salt, SALT_SIZE, 
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
        /* User wants manual input to be encrypted */
        /* Do Nothing */
    }
    pwdKey[strlen(pwdKey) - 1] = 0;
    /* restore terminal */
    if (tcsetattr(fileno(stdin), TCSANOW, &oflags) != 0) {
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
    int len = strlen(s); /* length of string*/

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

/*
 * hashing function 
 */
int wolfsslHash(char* in, char* len, char* out, char* alg, int size)
{
#ifdef HAVE_BLAKE2
    Blake2b hash;               /* blake2b declaration */
#endif
    FILE*   inFile;             /* input file */
    FILE*   outFile;            /* output file */

    byte*   input;              /* input buffer */
    byte*   output;             /* output buffer */

    int     ret = -1;                /* return variable */
    int     length;             /* length of hash */

    output = malloc(size);
    memset(output, 0, size);

    /* opens input file */
    inFile = fopen(in, "rb");
    if (inFile == NULL) {
        /* if no input file was provided */
        if (len != NULL)
            /* if length was provided */
            length = atoi(len);
        else
            length = LENGTH_IN;

        input = malloc(length);
        memset(input, 0, length);
        for (i = 0; i < length; i++) {
            /* copies text from in to input */
            if (i <= LENGTH_IN ) {
                input[i] = in[i];
            }
        }
    }
    else {
        /* if input file provided finds end of file for length */
        fseek(inFile, 0, SEEK_END);
        int leng = ftell(inFile);
        fseek(inFile, 0, SEEK_SET);

        if (len != NULL) {
            /* if length is provided */
            length = atoi(len);
        }
        else 
            length = leng;

        input = malloc(length+1);
        memset(input, 0, length+1);
        if (input == NULL) {
            printf("Failed to create input buffer\n");
            return FATAL_ERROR;
        }
        ret = fread(input, 1, length, inFile);
        fclose(inFile);
    }
    /* hashes using accepted algorithm */
#ifndef NO_MD5    
    if (strcmp(alg, "-md5") == 0) {
        ret = Md5Hash(input, length, output);
    }
#endif
#ifndef NO_SHA  
    else if (strcmp(alg, "-sha") == 0) {
        ret = ShaHash(input, length, output);
    }
#endif
#ifndef NO_SHA256  
    else if (strcmp(alg, "-sha256") == 0) {
        ret = Sha256Hash(input, length, output);
    }
#endif
#ifdef CYASSL_SHA384
    else if (strcmp(alg, "-sha384") == 0) {
        ret = Sha384Hash(input, length, output);
    }
#endif
#ifdef CYASSL_SHA512
    else if (strcmp(alg, "-sha512") == 0) {
        ret = Sha512Hash(input, length, output);
    }
#endif
#ifdef HAVE_BLAKE2
    else if (strcmp(alg, "-blake2b") == 0) { 
        ret = InitBlake2b(&hash, size);
        ret = Blake2bUpdate(&hash, input, length);
        ret = Blake2bFinal(&hash, output, size);
    }
#endif
    if (ret == 0) {
        /* if no errors so far */
        if (out != NULL) {
            /* if output file provided */
            outFile = fopen(out, "wb");
            if (outFile != NULL) {
                /* if outFile exists */
                for (i = 0; i < size; i++) {
                    /* writes hashed output to outFile */
                    fprintf(outFile, "%02x", output[i]);
                }
                fclose(outFile);
            }
        }
        else {
            /*  if no output file */
            for (i = 0; i < size; i++) {
                /* write hashed output to terminal */
                printf("%02x", output[i]);
            }
            printf("\n");
        }
    }

    /* closes the opened files and frees the memory */
    memset(input, 0, length);
    memset(output, 0, size);
    free(input);
    free(output);
    return ret;
}
