/* wolfsslSetup.c
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

#define LENGTH_IN       (int)strlen(in)      /* type cast unsigned int to int */

int wolfsslSetup(int argc, char** argv, char action)
{
    char     outNameE[256] = "encrypted"; /* default outFile for encrypt */
    char     outNameD[256] = "decrypted"; /* default outfile for decrypt */
    char     inName[256] = "wolfSSL Command Line Utility Default Input ";

    char*    name = NULL;       /* string of algorithm, mode, keysize */
    char*    alg = NULL;        /* algorithm from name */
    char*    mode = NULL;       /* mode from name */
    char*    out = outNameE;    /* default output file name */
    char*    in = inName;       /* default in data */
    byte*    pwdKey = NULL;     /* password for generating pwdKey */
    byte*    key = NULL;        /* user set key NOT PWDBASED */
    byte*    iv = NULL;         /* iv for initial encryption */


    int      size       =   0;  /* keysize from name */
    int      ret        =   0;  /* return variable */
    int      block      =   0;  /* block size based on algorithm */
    int      pwdKeyChk  =   0;  /* if a pwdKey has been provided */
    int      ivCheck    =   0;  /* if the user sets the IV explicitly */
    int      keyCheck   =   0;  /* if ivCheck is 1 this should be set also */
    int      inCheck    =   0;  /* if input has been provided */
    int      outCheck   =   0;  /* if output has been provided */
    int      mark       =   0;  /* used for getting file extension of in */  
    int      i          =   0;  /* loop counter */
    int      eCheck     =   0;  /* if user is encrypting data */
    int      dCheck     =   0;  /* if user is decrypting data */
    int      inputHex   =   0;  /* if user is encrypting hexidecimal stuff */
    int      keyType    =   0;  /* tells Decrypt which key it will be using 
                                 * 1 = password based key, 2 = user set key 
                                 */
    word32   ivSize     =   0;  /* IV if provided should be 2*block */
    word32   numBits    =   0;  /* number of bits in argument from the user */

    if (action == 'e')
        eCheck = 1;
    if (action == 'd')
        dCheck = 1;

    /* help checking */
    if (argc == 2) {
        wolfsslHelp();
        return 0;
    }

    for (i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-help") == 0) {
            wolfsslHelp();
            return 0;
        }
    }

    name = argv[2];
    /* gets blocksize, algorithm, mode, and key size from name argument */
    block = wolfsslGetAlgo(name, &alg, &mode, &size);

    if (block != FATAL_ERROR) {
        pwdKey = (byte*) malloc(size);
        iv = (byte*) malloc(block);
        key = (byte*) malloc(size);

        /* Start at the third flag entered */
        i = 3;
        do {
            if (argv[i] == NULL){
                break;
            }
            else if (strcmp(argv[i], "-o") == 0 && argv[i+1] != NULL) {
                /* output file */
                out = argv[i+1];
                outCheck = 1;
                i+=2;
                /* it is mandatory that this be set last */
                continue;
            }

            else if (strcmp(argv[i], "-i") == 0 && argv[i+1] != NULL) {
                 /* input file/text */
                in = argv[i+1];
                inCheck = 1;
                /* continue while out check not equal 1 */
                i+=2;
                continue;
            }

            else if (strcmp(argv[i], "-p") == 0 && argv[i+1] != NULL) {
                /* password pwdKey */
                memcpy(pwdKey, argv[i+1], size);
                pwdKeyChk = 1;
                keyType = 1;
                i+=2;
                continue;
                 
            }
            else if (strcmp(argv[i], "-x") == 0) {
                /* using hexidecimal format */
                inputHex = 1;
                i++;
                continue;
                 
            }
            else if (strcmp(argv[i], "-V") == 0 && argv[i+1] != NULL) {
                /* iv for encryption */
                if (pwdKeyChk == 1) {
                    printf("Invalid option, attempting to use IV with password"
                           " based key.");
                    wolfsslFreeBins(pwdKey, iv, key, NULL, NULL);
                    return FATAL_ERROR;
                }
                 ivSize = block*2;
                if (strlen(argv[i+1]) != ivSize) {
                    printf("Invalid IV. Must match algorithm block size.\n");
                    printf("Invalid IV size was: %d.\n", 
                                                       (int) strlen(argv[i+1]));
                    printf("size of IV expected was: %d.\n", ivSize);
                    wolfsslFreeBins(pwdKey, iv, key, NULL, NULL);
                    return FATAL_ERROR;                    
                }
                else {
                    char ivString[strlen(argv[i+1])];
                    strcpy(ivString, argv[i+1]);
                    ret = wolfsslHexToBin(ivString, &iv, &ivSize,
                                            NULL, NULL, NULL,
                                            NULL, NULL, NULL,
                                            NULL, NULL, NULL);
                    if (ret != 0) {
                        printf("failed during conversion of IV, ret = %d\n", 
                                                                           ret);
                        wolfsslFreeBins(pwdKey, iv, key, NULL, NULL);
                        return -1;
                    }
                    ivCheck = 1;
                    i+=2;
                    continue;
                }
            }
            else if (strcmp(argv[i], "-K") == 0 && argv[i+1] != NULL) {
                /* 2 characters = 1 byte. 1 byte = 8 bits
                 * number of characters / 2 = bytes
                 * bytes * 8 = bits 
                 */
                numBits = (int) (strlen(argv[i+1]) / 2 ) * 8;
                /* Key for encryption */
                if ((int)numBits != size) {
                    printf("Length of key provided was: %d.\n", numBits);
                    printf("Length of key expected was: %d.\n", size);
                    printf("Invalid Key. Must match algorithm key size.\n");
                    wolfsslFreeBins(pwdKey, iv, key, NULL, NULL);
                    return FATAL_ERROR;
                }
                else {
                    char keyString[strlen(argv[i+1])];
                    strcpy(keyString, argv[i+1]);
                    ret = wolfsslHexToBin(keyString, &key, &numBits,
                                            NULL, NULL, NULL,
                                            NULL, NULL, NULL,
                                            NULL, NULL, NULL);
                     if (ret != 0) {
                        printf("failed during conversion of Key, ret = %d\n", 
                                                                           ret);
                        wolfsslFreeBins(pwdKey, iv, key, NULL, NULL);
                        return -1;
                    }
                    keyCheck = 1;
                    keyType = 2;
                    i+=2;
                    continue;
                }
            }
            else {
                i++; continue;
            }

        }while(i < 15);

        if (inCheck == 0 && eCheck == 1) {
            in = inName;
            /* if no input is provided */
            printf("No input was provided, but do not worry! We will encrypt"
                    " the string:\n\"%s\" for you.\n\n", inName);
            inCheck = 1;
        }

        if (eCheck == 1 && dCheck == 1) {
            printf("You want to encrypt and decrypt simultaneously? That does"
                    "not make sense...\n");
            wolfsslFreeBins(pwdKey, iv, key, NULL, NULL);
            return FATAL_ERROR;
        }

        if (inCheck == 0 && dCheck == 1) {
            printf("We are so sorry but you must specify what it is you are "
                    "trying to decrypt.\n");
            wolfsslFreeBins(pwdKey, iv, key, NULL, NULL);
            return FATAL_ERROR;
        }

        if (pwdKeyChk == 0 && keyCheck == 0) {
            /* if no pwdKey is provided */
            printf("Please enter a custom pwdKey, or simply hit\n\"Enter\" to "
                    "have a non-password iv generated for you\n");
            ret = wolfsslNoEcho((char*)pwdKey, size);
            pwdKeyChk = 1;
        }

        if (ivCheck == 1) {
            if (keyCheck == 0) {
                printf("IV was explicitly set, but no -K <key> was set. User\n"
                    " needs to provide a non-password based key when setting"
                        " the IV.\n");
                wolfsslFreeBins(pwdKey, iv, key, NULL, NULL);
                return FATAL_ERROR;
            }
        }

        if (pwdKeyChk == 1 && keyCheck == 1) {
            memset(pwdKey, 0, size);
        }

        /* encryption function call */
        if (eCheck == 1) {
            
            printf("\n");
            if (outCheck == 0 && ret == 0) {
                printf("No outfile was provided, "
                        "but do not worry! We made one");
                printf(" for you.\nLook for a file named: %s\n\n", outNameE);
                /* gets file extension of input type */
                for (i = 0; i < LENGTH_IN; i++) {
                    if ((in[i] == '.') || (mark == 1)) {
                        mark = 1;
                        wolfsslAppend(out, in[i]);
                    }
                }
            }
            ret = wolfsslEncrypt(alg, mode, pwdKey, key, size, in, out, 
                    iv, block, ivCheck, inputHex);
        }
        /* decryption function call */
        else if (dCheck == 1) {
            if (outCheck == 0 && ret == 0) {
                out = outNameD;
                printf("No outfile was provided, "
                        "but do not worry! We made one");
                printf(" for you.\nLook for a file named: %s\n\n", outNameD);
                /* gets file extension of input type */
                for (i = 0; i < LENGTH_IN; i++) {
                    if ((in[i] == '.') || (mark == 1)) {
                        mark = 1;
                        wolfsslAppend(out, in[i]);
                    }
                }
            }
            ret = wolfsslDecrypt(alg, mode, pwdKey, key, size, in, out, 
                    iv, block, keyType);
        }
        else {
            wolfsslHelp();
        }
        /* clear and free data */
        memset(key, 0, size);
        memset(pwdKey, 0, size);
        memset(iv, 0, block);
        wolfsslFreeBins(pwdKey, iv, key, NULL, NULL);
    }
    else
        ret = FATAL_ERROR;
    return ret;
}
