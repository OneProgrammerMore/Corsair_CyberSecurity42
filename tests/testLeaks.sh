#!/bin/bash

#Features Leak Checking:
#	-p (Done)
#	-f (Done)
#	-c (Done)
#	-x (Done)
#	-g (Done)
#	-d (Done)
#	-e (Done) 

#Remember - Compile with -dgb as:
#gcc -o corsair -std=c11 -Wall -ggdb3 corsair.c -lssl -lcrypto -w -lm
#gcc -o ../binaries/corsair -std=c11 -Wall -ggdb3 corsair.c -lssl -lcrypto -w -lm

#Call test as 
#./testLeaks.sh | grep -C 4 -E "echo|error|fault|-----"
#Or better:
#./testLeaks.sh | grep -e echo -e error -e fault
#Note: Some warnigns/errors may appear as the program creates the directories.

#Config variables
dirValResOut="./valgrindRes21/"
pathCorsairBin="../binaries/corsair"
dirExamplesPath="./../examples/challenge_corsair/"


mkdir -p $dirValResOut

#------------------------------ X GENERATE CRACKABLE KEYS --------------------------------
echo ------------------------------ X GENERATE CRACKABLE KEYS --------------------------------
valgrind --log-file="$dirValResOut"Xout01.file --leak-check=yes --tool=memcheck "$pathCorsairBin" -x  4 -o "$dirValResOut"valXOut01/
valgrind --log-file="$dirValResOut"XTout01.file --leak-check=yes  --track-origins=yes --tool=memcheck "$pathCorsairBin" -x  4 -o "$dirValResOut"valXOut02/
valgrind --log-file="$dirValResOut"XFout01.file --leak-check=full --show-leak-kinds=all --track-origins=yes --tool=memcheck "$pathCorsairBin" -x  4 -o "$dirValResOut"valXOut03/
#--leak-check=full --show-leak-kinds=all



#------------------------------ P CRACK KEYS IN PATH --------------------------------
echo ------------------------------ P CRACK KEYS IN PATH --------------------------------

valgrind --log-file="$dirValResOut"Pout01.file --leak-check=yes --tool=memcheck "$pathCorsairBin" -p "$dirExamplesPath"challenge_corsair/ -o "$dirValResOut"
valgrind --log-file="$dirValResOut"PTout01.file --leak-check=yes  --track-origins=yes --tool=memcheck "$pathCorsairBin" -p "$dirExamplesPath"challenge_corsair/ -o "$dirValResOut"valPOut02/
valgrind --log-file="$dirValResOut"PFout01.file --leak-check=full --show-leak-kinds=all --track-origins=yes --tool=memcheck "$pathCorsairBin" -p "$dirExamplesPath"challenge_corsair/ -o "$dirValResOut"valPOut03/


#------------------------------ G GENERATE N NOT CRACKABLE KEYS  --------------------------------
echo #------------------------------ G GENERATE N NOT CRACKABLE KEYS  --------------------------------
valgrind --log-file="$dirValResOut"Gout01.file --leak-check=yes --tool=memcheck "$pathCorsairBin" -g 5 -o "$dirValResOut"valGOut01/
valgrind --log-file="$dirValResOut"GTout01.file --leak-check=yes  --track-origins=yes --tool=memcheck "$pathCorsairBin" -g 5 -o "$dirValResOut"valGOut02/
valgrind --log-file="$dirValResOut"GFout01.file --leak-check=full --show-leak-kinds=all  --track-origins=yes --tool=memcheck "$pathCorsairBin" -g 5 -o "$dirValResOut"valGOut03/



#------------------------------ C GENERATE KEY FROM BIGNUM --------------------------------
echo ------------------------------ C GENERATE KEY FROM BIGNUM --------------------------------
valgrind --log-file="$dirValResOut"Cout01.file --leak-check=yes --tool=memcheck "$pathCorsairBin" -o "$dirValResOut"valCOut01/ \
 -C 171668005736312320838163729952276949982854994415199773193618288867548827965639919410493652712853022122316617758428088247128886690354536714915038974870406560317128022740325354738145914533499826880951735986746064320374657699657389640017872235510897148538622762812562873470945672684855488701689730647941548075157 \
 140475930401500496299033227376073592513957374789466409611614533193510115385485804618671031646238770587450949615868649317352271163989937507134019778215900891156904323325312273509229976889368765557901489364359229830146882049111224527121650805096088466207983336985717339536941332815164618665653689103167521230319


valgrind --log-file="$dirValResOut"CTout01.file --leak-check=yes  --track-origins=yes --tool=memcheck "$pathCorsairBin"  -o "$dirValResOut"valCOut02/ \
 -C 171668005736312320838163729952276949982854994415199773193618288867548827965639919410493652712853022122316617758428088247128886690354536714915038974870406560317128022740325354738145914533499826880951735986746064320374657699657389640017872235510897148538622762812562873470945672684855488701689730647941548075157 \
 140475930401500496299033227376073592513957374789466409611614533193510115385485804618671031646238770587450949615868649317352271163989937507134019778215900891156904323325312273509229976889368765557901489364359229830146882049111224527121650805096088466207983336985717339536941332815164618665653689103167521230319


valgrind --log-file="$dirValResOut"CFout01.file --leak-check=full --show-leak-kinds=all --track-origins=yes --tool=memcheck "$pathCorsairBin"  -o "$dirValResOut"valCOut03/ \
 -C 171668005736312320838163729952276949982854994415199773193618288867548827965639919410493652712853022122316617758428088247128886690354536714915038974870406560317128022740325354738145914533499826880951735986746064320374657699657389640017872235510897148538622762812562873470945672684855488701689730647941548075157 \
 140475930401500496299033227376073592513957374789466409611614533193510115385485804618671031646238770587450949615868649317352271163989937507134019778215900891156904323325312273509229976889368765557901489364359229830146882049111224527121650805096088466207983336985717339536941332815164618665653689103167521230319




#------------------------------ E ENCRYPT TEXT --------------------------------
echo ------------------------------ E ENCRYPT TEXT --------------------------------

dirValResOutEncrypt="$dirValResOut""encryptFunc/"
mkdir -p $dirValResOutEncrypt

valgrind --log-file="$dirValResOut"Eout01.file --leak-check=yes --tool=memcheck  \
"$pathCorsairBin" -e "$dirExamplesPath"encryptFunc/publicKey_01.pem "$dirExamplesPath"encryptFunc/encryptText.txt -o "$dirValResOutEncrypt"

valgrind --log-file="$dirValResOut"ETout01.file --leak-check=yes  --track-origins=yes --tool=memcheck  \
"$pathCorsairBin" -e "$dirExamplesPath"encryptFunc/publicKey_01.pem "$dirExamplesPath"encryptFunc/encryptText.txt -o "$dirValResOutEncrypt"

valgrind --log-file="$dirValResOut"EFout01.file --leak-check=full --show-leak-kinds=all  --track-origins=yes --tool=memcheck  \
"$pathCorsairBin" -e "$dirExamplesPath"encryptFunc/publicKey_01.pem "$dirExamplesPath"encryptFunc/encryptText.txt -o "$dirValResOutEncrypt"

#------------------------------ D DECRYPT BIN --------------------------------
echo ------------------------------ D DECRYPT BIN --------------------------------

dirValResOutDecrypt="$dirValResOut""decryptFunc/"
mkdir -p $dirValResOutDecrypt



valgrind --log-file="$dirValResOut"Dout01.file --leak-check=yes --tool=memcheck  \
"$pathCorsairBin" -d "$dirExamplesPath"decryptFunc/29_privateKey.pem "$dirExamplesPath"decryptFunc/29.bin -o "$dirValResOutDecrypt"

valgrind --log-file="$dirValResOut"DTout01.file --leak-check=yes  --track-origins=yes --tool=memcheck  \
"$pathCorsairBin" -d "$dirExamplesPath"decryptFunc/29_privateKey.pem "$dirExamplesPath"decryptFunc/29.bin -o "$dirValResOutDecrypt"

valgrind --log-file="$dirValResOut"DFout01.file --leak-check=full --show-leak-kinds=all --track-origins=yes --tool=memcheck  \
"$pathCorsairBin" -d "$dirExamplesPath"decryptFunc/29_privateKey.pem "$dirExamplesPath"decryptFunc/29.bin -o "$dirValResOutDecrypt"


#------------------------------ F CRACK KEYS IN FILES --------------------------------
echo ------------------------------ F CRACK KEYS IN FILES --------------------------------

dirValResOut4Files="$dirValResOut""4FilesFunc/"
mkdir -p $dirValResOut4Files

valgrind --log-file="$dirValResOut"Fout01.file --leak-check=yes --tool=memcheck  \
"$pathCorsairBin" -f "$dirExamplesPath"challenge_corsair/29.pem "$dirExamplesPath"challenge_corsair/82.pem "$dirExamplesPath"challenge_corsair/29.bin "$dirExamplesPath"challenge_corsair/82.bin -o "$dirValResOut4Files"


valgrind --log-file="$dirValResOut"FTout01.file --leak-check=yes  --track-origins=yes --tool=memcheck  \
"$pathCorsairBin" -f "$dirExamplesPath"challenge_corsair/29.pem "$dirExamplesPath"challenge_corsair/82.pem "$dirExamplesPath"challenge_corsair/29.bin "$dirExamplesPath"challenge_corsair/82.bin -o "$dirValResOut4Files"


valgrind --log-file="$dirValResOut"FFout01.file --leak-check=full --show-leak-kinds=all  --track-origins=yes --tool=memcheck  \
"$pathCorsairBin" -f "$dirExamplesPath"challenge_corsair/29.pem "$dirExamplesPath"challenge_corsair/82.pem "$dirExamplesPath"challenge_corsair/29.bin "$dirExamplesPath"challenge_corsair/82.bin -o "$dirValResOut4Files"



