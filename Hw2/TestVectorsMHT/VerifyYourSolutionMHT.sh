#!/bin/bash

gcc mht.c -lcrypto -o mht

clean_file() {
    tmp_file=$(mktemp)
    tr -d '\r' < "$1" > "$tmp_file"
    sed -i 's/[[:space:]]*$//' "$tmp_file"
    mv "$tmp_file" "$1"
}

echo "Testing Messages1.txt..."
for i in M1 M2 M3 M4 M5 M6 M7 M8
do
   echo "Testing $i..."
   rm -f TheRoot.txt ThePath.txt mht.log
   
   ./mht Messages1.txt $i >> mht.log
   
   clean_file "ThePath.txt"
   clean_file "CorrectPath1$i.txt"
   
   #=========================================
   if cmp -s "TheRoot.txt" "CorrectRoot1.txt"
   then
      echo "Your Root 1 is correct."
   else
      echo "Your Root 1 does not match!"
   fi 
   #=========================================
   if cmp -s "ThePath.txt" "CorrectPath1$i.txt"
   then
      echo "Path $i is valid."
   else
      echo "Path $i is wrong!"
      echo "Expected path (CorrectPath1$i.txt) hex dump:"
      xxd "CorrectPath1$i.txt"
      echo "Your path (ThePath.txt) hex dump:"
      xxd "ThePath.txt"
      echo "File sizes:"
      wc -c "CorrectPath1$i.txt" "ThePath.txt"
   fi 
   #=========================================
done

echo "================================"

echo "Testing Messages2.txt..."
for j in M1 M2 M3 M4 M5 M6 M7 M8
do
   echo "Testing $j..."
   rm -f TheRoot.txt ThePath.txt mht2.log
   
   ./mht Messages2.txt $j >> mht2.log
   
   clean_file "ThePath.txt"
   clean_file "CorrectPath2$j.txt"
   
   #=========================================
   if cmp -s "TheRoot.txt" "CorrectRoot2.txt"
   then
      echo "Your Root 2 is correct."
   else
      echo "Your Root 2 does not match!"
   fi 
   #=========================================
   if cmp -s "ThePath.txt" "CorrectPath2$j.txt"
   then
      echo "Path $j is valid."
   else
      echo "Path $j is wrong!"
      echo "Expected path (CorrectPath2$j.txt) hex dump:"
      xxd "CorrectPath2$j.txt"
      echo "Your path (ThePath.txt) hex dump:"
      xxd "ThePath.txt"
      echo "File sizes:"
      wc -c "CorrectPath2$j.txt" "ThePath.txt"
   fi 
   #=========================================
done