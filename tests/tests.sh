#Test utility functionality
#!/bin/bash
PAT="/home/khimes"
WOLFSSL="wolfssl"
ENC="-e"
DEC="-d"
HASH="-h"
BENCH="-b"
AES="aes-cbc-"
AES2="aes-ctr-"
DES="3des-cbc-"
CAM="camellia-cbc-"
M="-md5"
SHA="-sha"
SHA2="-sha256"
SHA3="-sha384"
SHA5="-sha512"
BLAKE="-blake2b"
zero=0
OPTS="$PAT/true_cyassl_clone/cyassl/options.h"

function crypto() {
    COUNTER=8
    SIZEF=1
    SIZET=1

    until [ $COUNTER -lt 1 ]; do
        echo Creating Test File of Size $SIZEF...
        IN=$(mktemp /tmp/input.XXXXXXXXXX) || { echo "Failed to create temp file"; exit 1; }
        OUT=$(mktemp /tmp/output.XXXXXXXXXX) || { echo "Failed to create temp file"; exit 1; }
        KEY=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 10 | head -n 1)
        RANDF=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w $SIZEF | head -n 1)
        RANDT=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w $SIZET | head -n 1)
    
        echo $RANDF  >> $IN
            
        echo $WOLFSSL $ENC $1 size: $SIZEF bytes
        $WOLFSSL $ENC $1  -p $KEY -i $IN -o $OUT
        $WOLFSSL $DEC $1  -p $KEY -i $OUT -o $IN
        echo $WOLFSSL $ENC $1 -i $RANDT
        $WOLFSSL $ENC $1  -p $KEY -i $RANDT -o $OUT
        $WOLFSSL $DEC $1  -p $KEY -i $OUT -o $IN
          
        rm -f $OUT
        rm -f $in
   
        let COUNTER-=1
        let SIZEF*=10
        let SIZET+=10
    done
}

function hashing() {
    COUNTER=8
    SIZEF=1
    SIZET=1

    until [ $COUNTER -lt 1 ]; do
        echo Creating File of Size $SIZEF...
        IN=$(mktemp /tmp/input.XXXXXXXXXX) || { echo "Failed to create temp file"; exit 1; }
        OUT=$(mktemp /tmp/output.XXXXXXXXXX) || { echo "Failed to create temp file"; exit 1; }
        RANDF=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w $SIZEF | head -n 1)
        RANDT=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w $SIZET | head -n 1)
        echo $RANDF >> $IN
 
        echo $WOLFSSL -h $1 size: $SIZEF bytes
        $WOLFSSL -h $1 -i $IN -o $OUT
        echo $WOLFSSL -h $1 -i $RANDT
        $WOLFSSL -h $1 -i $RANDT -o $OUT

        rm -f $IN
        rm -f $OUT
    
        let COUNTER-=1
        let SIZEF*=10
        let SIZET+=10
    done
}
crypto $AES\128
crypto $AES\192
crypto $AES\256

grep -q "CYASSL_AES_COUNTER" $OPTS && if [[ $? -eq $zero ]]; then
    crypto $AES2\128
    crypto $AES2\192
    crypto $AES2\256
fi

crypto $DES\56
crypto $DES\112
crypto $DES\168
grep -q "HAVE_CAMELLIA" $OPTS && if [[ $? -eq $zero ]]; then
    crypto $CAM\128
    crypto $CAM\192
    crypto $CAM\256
fi

hashing $M
hashing $SHA
hashing $SHA2

grep -q "CYASSL_SHA384" $OPTS && if [[ $? -eq $zero ]]; then
    hashing $SHA3
fi

grep -q "CYASSL_SHA512" $OPTS && if [[ $? -eq $zero ]]; then
    hashing $SHA5
fi

grep -q "HAVE_BLAKE2" $OPTS && if [[ $? -eq $zero ]]; then
    hashing $BLAKE
fi
$WOLFSSL -b -t 1 -all

rm enc.txt
rm converting.txt
