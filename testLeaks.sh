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


dirValRes="valgrindRes20/"
#dirValResOut="./valgrindRes08/"
dirValResOut="./""$dirValRes"
mkdir $dirValRes

#------------------------------ X GENERATE CRACKABLE KEYS --------------------------------
valgrind --log-file="$dirValRes"Xout01.file --leak-check=yes --tool=memcheck ./corsair -x  4 -o "$dirValResOut"valXOut01/
valgrind --log-file="$dirValRes"XTout01.file --leak-check=yes  --track-origins=yes --tool=memcheck ./corsair -x  4 -o "$dirValResOut"valXOut02/
valgrind --log-file="$dirValRes"XFout01.file --leak-check=full --show-leak-kinds=all --track-origins=yes --tool=memcheck ./corsair -x  4 -o "$dirValResOut"valXOut03/
#--leak-check=full --show-leak-kinds=all



#------------------------------ P CRACK KEYS IN PATH --------------------------------
valgrind --log-file="$dirValRes"Pout01.file --leak-check=yes --tool=memcheck ./corsair -p "$dirValRes"/valXOut01/ -o "$dirValResOut"
valgrind --log-file="$dirValRes"PTout01.file --leak-check=yes  --track-origins=yes --tool=memcheck ./corsair -p "$dirValRes"/valXOut01/ -o "$dirValResOut"valPOut02/
valgrind --log-file="$dirValRes"PFout01.file --leak-check=full --show-leak-kinds=all --track-origins=yes --tool=memcheck ./corsair -p "$dirValRes"/valXOut01/ -o "$dirValResOut"valPOut03/


#------------------------------ G GENERATE N NOT CRACKABLE KEYS  --------------------------------
valgrind --log-file="$dirValRes"Gout01.file --leak-check=yes --tool=memcheck ./corsair -g 5 -o "$dirValResOut"valGOut01/
valgrind --log-file="$dirValRes"GTout01.file --leak-check=yes  --track-origins=yes --tool=memcheck ./corsair -g 5 -o "$dirValResOut"valGOut02/
valgrind --log-file="$dirValRes"GFout01.file --leak-check=full --show-leak-kinds=all  --track-origins=yes --tool=memcheck ./corsair -g 5 -o "$dirValResOut"valGOut03/



#------------------------------ C GENERATE KEY FROM BIGNUM --------------------------------
valgrind --log-file="$dirValRes"Cout01.file --leak-check=yes --tool=memcheck ./corsair -o "$dirValResOut"valCOut01/ \
 -C 171668005736312320838163729952276949982854994415199773193618288867548827965639919410493652712853022122316617758428088247128886690354536714915038974870406560317128022740325354738145914533499826880951735986746064320374657699657389640017872235510897148538622762812562873470945672684855488701689730647941548075157 \
 140475930401500496299033227376073592513957374789466409611614533193510115385485804618671031646238770587450949615868649317352271163989937507134019778215900891156904323325312273509229976889368765557901489364359229830146882049111224527121650805096088466207983336985717339536941332815164618665653689103167521230319


valgrind --log-file="$dirValRes"CTout01.file --leak-check=yes  --track-origins=yes --tool=memcheck ./corsair  -o "$dirValResOut"valCOut02/ \
 -C 171668005736312320838163729952276949982854994415199773193618288867548827965639919410493652712853022122316617758428088247128886690354536714915038974870406560317128022740325354738145914533499826880951735986746064320374657699657389640017872235510897148538622762812562873470945672684855488701689730647941548075157 \
 140475930401500496299033227376073592513957374789466409611614533193510115385485804618671031646238770587450949615868649317352271163989937507134019778215900891156904323325312273509229976889368765557901489364359229830146882049111224527121650805096088466207983336985717339536941332815164618665653689103167521230319


valgrind --log-file="$dirValRes"CFout01.file --leak-check=full --show-leak-kinds=all --track-origins=yes --tool=memcheck ./corsair  -o "$dirValResOut"valCOut03/ \
 -C 171668005736312320838163729952276949982854994415199773193618288867548827965639919410493652712853022122316617758428088247128886690354536714915038974870406560317128022740325354738145914533499826880951735986746064320374657699657389640017872235510897148538622762812562873470945672684855488701689730647941548075157 \
 140475930401500496299033227376073592513957374789466409611614533193510115385485804618671031646238770587450949615868649317352271163989937507134019778215900891156904323325312273509229976889368765557901489364359229830146882049111224527121650805096088466207983336985717339536941332815164618665653689103167521230319




#------------------------------ E ENCRYPT TEXT --------------------------------

dirValResOutEncrypt="$dirValResOut""encryptFunc/"
mkdir dirValResOutEncrypt

valgrind --log-file="$dirValRes"Eout01.file --leak-check=yes --tool=memcheck  \
./corsair -e ./Sources/encryptFunc/publicKey_01.pem ./Sources/encryptFunc/encryptText.txt -o "$dirValResOutEncrypt"

valgrind --log-file="$dirValRes"ETout01.file --leak-check=yes  --track-origins=yes --tool=memcheck  \
./corsair -e ./Sources/encryptFunc/publicKey_01.pem ./Sources/encryptFunc/encryptText.txt -o "$dirValResOutEncrypt"

valgrind --log-file="$dirValRes"EFout01.file --leak-check=full --show-leak-kinds=all  --track-origins=yes --tool=memcheck  \
./corsair -e ./Sources/encryptFunc/publicKey_01.pem ./Sources/encryptFunc/encryptText.txt -o "$dirValResOutEncrypt"

#------------------------------ D DECRYPT BIN --------------------------------

dirValResOutDecrypt="$dirValResOut""decryptFunc/"
mkdir dirValResOutDencrypt



valgrind --log-file="$dirValRes"Dout01.file --leak-check=yes --tool=memcheck  \
./corsair -d ./Sources/decryptFunc/29_privateKey.pem ./Sources/decryptFunc/29.bin -o "$dirValResOutDecrypt"

valgrind --log-file="$dirValRes"DTout01.file --leak-check=yes  --track-origins=yes --tool=memcheck  \
./corsair -d ./Sources/decryptFunc/29_privateKey.pem ./Sources/decryptFunc/29.bin -o "$dirValResOutDecrypt"

valgrind --log-file="$dirValRes"DFout01.file --leak-check=full --show-leak-kinds=all --track-origins=yes --tool=memcheck  \
./corsair -d ./Sources/decryptFunc/29_privateKey.pem ./Sources/decryptFunc/29.bin -o "$dirValResOutDecrypt"


#------------------------------ F CRACK KEYS IN FILES --------------------------------

dirValResOut4Files="$dirValResOut""4FilesFunc/"
mkdir dirValResOut4Files

valgrind --log-file="$dirValRes"Fout01.file --leak-check=yes --tool=memcheck  \
./corsair -f ./Sources/challenge_corsair/29.pem ./Sources/challenge_corsair/82.pem ./Sources/challenge_corsair/29.bin ./Sources/challenge_corsair/82.bin -o "$dirValResOut4Files"


valgrind --log-file="$dirValRes"FTout01.file --leak-check=yes  --track-origins=yes --tool=memcheck  \
./corsair -f ./Sources/challenge_corsair/29.pem ./Sources/challenge_corsair/82.pem ./Sources/challenge_corsair/29.bin ./Sources/challenge_corsair/82.bin -o "$dirValResOut4Files"


valgrind --log-file="$dirValRes"FFout01.file --leak-check=full --show-leak-kinds=all  --track-origins=yes --tool=memcheck  \
./corsair -f ./Sources/challenge_corsair/29.pem ./Sources/challenge_corsair/82.pem ./Sources/challenge_corsair/29.bin ./Sources/challenge_corsair/82.bin -o "$dirValResOut4Files"



