/* wolfsslEncrypt.c
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
#define MAX             1024

int wolfsslEncrypt(char* alg, char* mode, byte* pwdKey, byte* key, int size, 
        char* in, char* out, byte* iv, int block, int ivCheck)
{
#ifndef NO_AES
    Aes aes;                        /* aes declaration */
#endif

#ifndef NO_DES3
    Des3 des3;                      /* 3des declaration */
#endif

#ifdef HAVE_CAMELLIA
    Camellia camellia;              /* camellia declaration */
#endif

    FILE*  tempInFile = NULL;       /* if user not provide a file */
    FILE*  inFile = NULL;           /* input file */
    FILE*  outFile = NULL;          /* output file */

    RNG     rng;                    /* random number generator declaration */
    byte*   input = NULL;           /* input buffer */
    byte*   userInputBuffer = NULL; /* buffer for not a file */
    byte*   output = NULL;          /* output buffer */
    byte    salt[SALT_SIZE] = {0};  /* salt variable */

    int     ret             = 0;    /* return variable */
    int     inputLength     = 0;    /* length of input */
    int     length          = 0;    /* total length */
    int     padCounter      = 0;    /* number of padded bytes */
    int     i               = 0;    /* loop variable */
    int     tempi           = 0;
    word32  tempMax         = MAX;  /* equal to max until padding */


    if (access (in, F_OK) == -1) {
        printf("file did not exist, encrypting string following \"-i\""
                "instead.\n");
        /* use user entered data to encrypt */
        inputLength = strlen(in);
        userInputBuffer = (byte*) malloc(inputLength);

        /* writes the entered text to the input buffer */
        memcpy(userInputBuffer, in, inputLength);

        /* open the file to write */
        tempInFile = fopen(in, "wb");
        fwrite(userInputBuffer, 1, inputLength, tempInFile);
        fclose(tempInFile);

        /* free buffer */
        free(userInputBuffer);
    }

    /* open the inFile in read mode */
    inFile = fopen(in, "rb");  

    /* find length */
    fseek(inFile, 0, SEEK_END);
    inputLength = ftell(inFile);
    fseek(inFile, 0, SEEK_SET);

    length = inputLength;

    /* Start up the random number generator */
    InitRng(&rng);

    /* pads the length until it matches a block / increases pad number */
    while (length % block != 0) {
        length++;
        padCounter++;
    }

    /* Ensure 1kB is evenly divisible by block size */
    if (MAX % block != 0) {
        printf("Bad Block.\n"); /* This should never happen */
        return ENCRYPT_ERROR;
    }
    if (length % block != 0) {
        /* ensure blocks will evenly fit into file */
        printf("Error with length mod block size.\n");
        return -1;
    }

    /* if the iv was not explicitly set, generate an iv and use the pwdKey */
    if (ivCheck == 0) {
        /* if the iv is not set, then generate it */
        printf("random IV being generated.\n");
        /* randomly generate iv if one has not been provided */
        ret = RNG_GenerateBlock(&rng, iv, block);
        if (ret != 0) {
            return ret;
        }
        /* stretches pwdKey to fit size based on wolfsslGetAlgo() */
        ret = wolfsslGenKey(&rng, pwdKey, size, salt, padCounter);
        if (ret != 0) {
            printf("failed to set pwdKey.\n");
            return ret;
        }
        /* move the generated pwdKey to "key" for encrypting */
        for (i = 0; i < size; i++) {
            key[i] = pwdKey[i];
        }
    }

    /* open the outFile in write mode */
    outFile = fopen(out, "wb");
    fwrite(salt, 1, SALT_SIZE, outFile);
    if (iv != NULL ) {
        printf("\nIV as printed to file.\n");
        for (tempi = 0; tempi < block; tempi++) {
            printf("%02x", iv[tempi]);
        }
    }
    printf("\n");
    fwrite(iv, 1, block, outFile);
    fclose(outFile);

    /* malloc a 1kB buffers */
    input = (byte*) malloc(MAX);
    output = (byte*) malloc(MAX);

    /* loop, encrypt 1kB at a time till length <= 0 */
    while (length > 0) {
        /* Read in 1kB to input[] */
        ret = fread(input, 1, MAX, inFile);
        if (ret != MAX) { /* we may have reached end of file */
            if (feof(inFile)) {

                printf("End of file reached, padding...\n");
                /* pad to end of block */
                for (i = ret ; i < (ret + padCounter); i++) {
                    printf("padd %d.\n", i);
                    input[i] = padCounter;
                }

                /* adjust tempMax for less than 1kB encryption */
                tempMax = ret + padCounter;
            } 
            else { /* otherwise we got a file read error */
                wolfsslFreeBins(input, output, NULL, NULL, NULL);
                return FREAD_ERROR;
            }
        }
        /* encrypt input[] to output[] and write to outFile */

        /* sets key encrypts the message to ouput from input length + padding */
#ifndef NO_AES
        if (strcmp(alg, "aes") == 0) {
            if (strcmp(mode, "cbc") == 0) {
                ret = AesSetKey(&aes, key, AES_BLOCK_SIZE, iv, AES_ENCRYPTION);
                if (ret != 0) {
                    printf("AesSetKey failed.\n");
                    wolfsslFreeBins(input, output, NULL, NULL, NULL);
                    return ret;
                }
                  if (iv != NULL ) {
            printf("\nIV before AesCbcEncrypt.\n");
            for (tempi = 0; tempi < block; tempi++) {
                printf("%02x", iv[tempi]);
            }
        }
        if (key != NULL) {
            printf("\nkey before AesCbcEncrypt.\n");
            for (tempi = 0; tempi < 128/8; tempi++) {
                printf("%02x", key[tempi]);
            }
        }
                ret = AesCbcEncrypt(&aes, output, input, tempMax);
                if (ret != 0) {
                    printf("AesCbcEncrypt failed.\n");
                    wolfsslFreeBins(input, output, NULL, NULL, NULL);
                    return ENCRYPT_ERROR;
                }
            }
#ifdef CYASSL_AES_COUNTER
            else if (strcmp(mode, "ctr") == 0) {
                /* if mode is ctr */
                AesSetKeyDirect(&aes, key, AES_BLOCK_SIZE, iv, AES_ENCRYPTION);
                AesCtrEncrypt(&aes, output, input, tempMax);
            }
#endif
        }
#endif
#ifndef NO_DES3
        if (strcmp(alg, "3des") == 0) {
            ret = Des3_SetKey(&des3, key, iv, DES_ENCRYPTION);
            if (ret != 0) {
                printf("Des3_SetKey failed.\n");
                wolfsslFreeBins(input, output, NULL, NULL, NULL);
                return ret;
            }
            ret = Des3_CbcEncrypt(&des3, output, input, tempMax);
            if (ret != 0) {
                printf("Des3_CbcEncrypt failed.\n");
                wolfsslFreeBins(input, output, NULL, NULL, NULL);
                return ENCRYPT_ERROR;
            }
        }
#endif
#ifdef HAVE_CAMELLIA
        if (strcmp(alg, "camellia") == 0) {
            ret = CamelliaSetKey(&camellia, key, block, iv);
            if (ret != 0) {
                printf("CamelliaSetKey failed.\n");
                wolfsslFreeBins(input, output, NULL, NULL, NULL);
                return ret;
            }
            if (strcmp(mode, "cbc") == 0) {
                CamelliaCbcEncrypt(&camellia, output, input, tempMax);
            }
            else {
                printf("Incompatible mode while using Camellia.\n");
                wolfsslFreeBins(input, output, NULL, NULL, NULL);
                return FATAL_ERROR;
            }
        }
#endif /* HAVE_CAMELLIA */

        
        if (iv != NULL ) {
            printf("\nIV before print.\n");
            for (tempi = 0; tempi < block; tempi++) {
                printf("%02x", iv[tempi]);
            }
        }
        if (key != NULL) {
            printf("\nkey before print.\n");
            for (tempi = 0; tempi < 128/8; tempi++) {
                printf("%02x", key[tempi]);
            }
        }
        if (output != NULL) {
            printf("\noutput buffer has: \n");
            for (tempi = 0; tempi < block; tempi++ ) {
                printf("%02x", output[tempi]);
            }
        }
        printf("\n");

        outFile = fopen(out, "ab");
      
        ret = fwrite(output, 1, tempMax, outFile);

        if (ret != (int) tempMax) {
            printf("wrote too much.\n");
        }
        fclose(outFile);

        length -= tempMax;
        if (length < 0)
            printf("length went past zero.\n");
        printf("1\n");
        if (input != NULL)
            memset(input, 0, tempMax); 
        printf("2\n");
        if (output != NULL)
            memset(output, 0, tempMax);
    }

    /* closes the opened files and frees the memory */
    printf("3\n");
    fclose(inFile);
    printf("4\n");
    wolfsslFreeBins(input, output, NULL, NULL, NULL);
    printf("5\n");
    if (key != NULL)
        memset(key, 0, size);
    printf("6\n");  
    if (iv != NULL)
        memset(iv, 0 , block);
    printf("7\n");  
    memset(alg, 0, size);
    printf("8\n");
    memset(mode, 0 , block);
    printf("9\n");
    return 0;
}