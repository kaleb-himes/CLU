/* cyassl.c
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

void help()
{
    printf("\nwolfSSL command line utility help menu\n\n");
    printf("-help           Help, print out this help menu\n\n");
    printf("Only use one of these ***************************************\n\n");
    printf("-e              Encrypt a file or some user input\n");
    printf("-d              Decrypt an encrypted file\n");
    printf("-h              Hash a file or input\n");
    printf("-b              Benchmark one of the algorithms\n\n");
    printf("*************************************************************\n\n");
    /*optional flags*/
    printf("Optional flags **********************************************\n\n");
    printf("-i              input file to manage\n");
    printf("-o              file to output as a result of option\n");
    printf("-p              user custom password\n");
    printf("-V              user custom IV\n");
    printf("-k              user custom key\n\n");
    printf("*************************************************************\n\n");
    printf("\nUSAGE: ./wolfssl COMMAND [optional flags]... [in_file, out_file]"
        "\n\n"
        "EXAMPLE: ./wolfssl -e -aes-cbc-128 -k Thi$i$myPa$$w0rd "
        " -i somejunk.txt -o encryptedjunk.txt\n\n"
        "NOTE: start with -e, -d, -h, or -b and end with"
        "-i <string or file name> -o <file name>.\n"
        "Other flags are optional with optional order.\n\n");
}

int main(int argc, char** argv)
{
    int ret = 0;
    int option;

    while ((option = getopt (argc, argv, "e:d:h:b:i:o:p:V:K:l:t:")) != -1)  { 
        switch (option) 
        {
            /* User wants to encrypt data or file*/ 
            case 'e':
                ret = wolfsslSetup(argc, argv, 'e');
                break;
                /* User wants to decrypt some data or file */    
            case 'd':
                ret = wolfsslSetup(argc, argv, 'd');
                break;
                /* User wants to hash some data/file */
            case 'h':
                ret = wolfsslHashSetup(argc, argv);
                break;   
            case 'b':
                ret = wolfsslBenchSetup(argc, argv);
                break;
            case 'i':/* will be handled by Setup function */
                break;
            case 'o':/* will be handled by Setup function */
                break;
            case 'p':/* will be handled by Setup function */
                break;
            case 'V':/* will be handled by Setup function */
                break;
            case 'K':/* will be handled by Setup function */
                break;
            case 'l':/* will be handled by hashSetup function */
                break;
            case 't':/* will be handled by benchSetup function */
                break;

            default:
                help();
        }
    }
    // ret = testHexToBin();
    return ret;
}