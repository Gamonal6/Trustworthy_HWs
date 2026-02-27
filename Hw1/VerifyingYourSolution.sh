gcc alice.c -lcrypto -o alice
gcc bob.c -lcrypto -o bob

for i in 1 2 3
do
./alice Message$i.txt SharedSeed$i.txt >> alice$i.log &
sleep 1
./bob SharedSeed$i.txt >> bob$i.log &
sleep 1
./alice Message$i.txt SharedSeed$i.txt >> alice$i.log &
sleep 1
#=========================================
if cmp -s "Key.txt" "CorrectKey$i.txt"
then
   echo "Key$i is valid."
else
   echo "Key$i does not match!"
fi 
#=========================================
if cmp -s "Ciphertext.txt" "CorrectCiphertext$i.txt"
then
   echo "Ciphertext$i is valid."
else
   echo "Ciphertext$i does not match!"
fi
#=========================================
if cmp -s "Plaintext.txt" "CorrectPlaintext$i.txt"
then
   echo "Plaintext$i is valid."
else
   echo "Plaintext$i does not match!"
fi
#=========================================
if cmp -s "Hash.txt" "CorrectHash$i.txt"
then
   echo "Hash$i is valid."
else
   echo "Hash$i does not match!"
fi 
#=========================================
echo "$(cat Acknowledgment.txt)"
#=========================================
echo "================================================="
done
