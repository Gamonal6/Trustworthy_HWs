gcc server.c -lssl -lcrypto -o Server
gcc client.c -lssl -lcrypto -o Client
gcc verify.c -lssl -lcrypto -o Verify

for i in 1 2 
do
./Server Challenge$i.txt Difficulty$i.txt >> Server$i.log
./Client puzzle_challenge.txt puzzle_k.txt >> Client$i.log
./Verify puzzle_challenge.txt puzzle_k.txt solution_nonce.txt >> Verify$i.log

if cmp -s "puzzle_challenge.txt" "correct_puzzle_challenge$i.txt"
then
   echo "Puzzle_challenge$i is valid."
else
   echo "Puzzle_challenge$i does not match!"
fi

if cmp -s "solution_nonce.txt" "correct_solution_nonce$i.txt"
then
   echo "Solution_nonce$i is valid."
else
   echo "Solution_nonce$i does not match!"
fi

if cmp -s "verification_result.txt" "correct_verification_result$i.txt"
then
   echo "Verification_result$i is valid."
else
   echo "Verification_result$i does not match!"
fi

done

# test with invalid solution
./Verify puzzle_challenge.txt puzzle_k.txt Invalid_Solution.txt >> Verify_invalid.log

if [ $? -ne 0 ]; then
    echo "Verify correctly rejected invalid solution."
else
    echo "Verify did not reject invalid solution!"
fi