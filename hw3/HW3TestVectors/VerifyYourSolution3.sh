
cmp_files() {
    cmp -s <(tr -d '\r' < "$1") <(tr -d '\r' < "$2")
}

gcc alice.c -lcrypto -o alice
gcc bob.c -lcrypto -o bob

for i in 1 2
do
./alice Messages$i.txt SharedSeed$i.txt >> alice$i.log
./bob SharedSeed$i.txt >> bob$i.log

#=========================================
if cmp_files "CorrectKeys$i.txt" "Keys.txt"
then
   echo "Your KEYs$i are correct."
else
   echo "Your KEYs$i do not match!"
fi 
#=========================================
if cmp_files "CorrectCiphertexts$i.txt" "Ciphertexts.txt"
then
   echo "Your CIPHERTEXTs$i are correct."
else
   echo "Your CIPHERTEXTs$i do not match!"
fi 
#=========================================
if cmp_files "CorrectIndividualHMACs$i.txt" "IndividualHMACs.txt"
then
   echo "Your Individual HMACs$i are correct."
else
   echo "Your Individual HMACs$i do not match!"
fi 
#=========================================
if cmp_files "CorrectAggregatedHMAC$i.txt" "AggregatedHMAC.txt"
then
   echo "Your Aggregated HMAC$i is correct."
else
   echo "Your Aggregated HMAC$i does not match!"
fi 
#=========================================
if cmp_files "CorrectPlaintexts$i.txt" "Plaintexts.txt";
then
   echo "Your Plaintexts$i are correct."
else
   echo "Your Plaintexts$i does not match!"
fi 
#=========================================
done
