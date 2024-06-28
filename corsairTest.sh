#!/bin/sh

#Call test as 
#./corsairTest.sh | grep -E "echo|error|fault"
#./corsairTest.sh | grep -e echo -e error -e fault

#Change following var to change output dir
dirTestRes="testRes08/"
#dirValResOut="./valgrindRes08/"
dirTestResOut="./""$dirTestRes"

mkdir $dirTestResOut

#--------------------------- HELP FUNCTION ---------------------------------------

echo echo ----- HELP FUNCTION ---

#Help function alone:
./corsair -h

#Help Function with other parameters at the end:
./corsair -h -p Sources/challenge_corsair/
./corsair -h -g 10

#Help Function with other parameters at the start:
./corsair -g 10 -h


#--------------------------- MAIN FUNCTION ---------------------------------------

echo echo ---- MAIN FUNCTION ------

#Test corsair main function with standard output path
./corsair -p ./Sources/challenge_corsair/

#Test corsair main function with setted output path at the end
./corsair -p ./Sources/challenge_corsair/ -o "$dirTestResOut"pFunc01/

#Test corsair main function with setted output path at the beggining
./corsair -o "$dirTestResOut"pFunc01/ -p ./Sources/challenge_corsair/ 

#------------------------- FILES FUNCTION ----------------------------------------

echo echo ---- FILES FUNCTION -----

#Test file function without setting output path:
./corsair -f ./Sources/challenge_corsair/29.pem ./Sources/challenge_corsair/82.pem ./Sources/challenge_corsair/29.bin ./Sources/challenge_corsair/82.bin

#Test file function setting output path at the end:
./corsair -f ./Sources/challenge_corsair/29.pem ./Sources/challenge_corsair/82.pem ./Sources/challenge_corsair/29.bin ./Sources/challenge_corsair/82.bin -o "$dirTestResOut"fFunc01/

#Test file function setting output path at the start:
./corsair -f ./Sources/challenge_corsair/29.pem ./Sources/challenge_corsair/82.pem ./Sources/challenge_corsair/29.bin ./Sources/challenge_corsair/82.bin -o "$dirTestResOut"fFunc02/

#------------------------- GENERATE FUNCTION ----------------------------------------

echo echo --- GENERATE FUNCTION ----

#Test generate function without setting output path
./corsair -g 10

#Test generate function setting output path at the end
./corsair -g 10  -o "$dirTestResOut"gFfunc01/

#Test generate function setting output path at the start
./corsair  -o "$dirTestResOut"gFfunc02/ -g 10


#--------------------- MAIN FUNCTION WITH GENERATED KEYS -------------------------------

echo echo -- MAIN FUNCTION WITH GENERATED KEYS --

#Test corsair main function with standard output path
./corsair -p "$dirTestResOut"gFfunc01/

#Test corsair main function with setted output path at the end
./corsair -p "$dirTestResOut"gFfunc01/ -o "$dirTestResOut"p_gFunc01/

#Test corsair main function with setted output path at the beggining
./corsair -o "$dirTestResOut"p_gFunc02/ -p "$dirTestResOut"gFfunc01/

#Test corsair main function with standard output path
./corsair -p "$dirTestResOut"gFfunc02/

#Test corsair main function with setted output path at the end
./corsair -p "$dirTestResOut"gFfunc01/ -o "$dirTestResOut"p_gFunc03/

#Test corsair main function with setted output path at the beggining
./corsair -o "$dirTestResOut"p_gFunc04/ -p "$dirTestResOut"gFfunc02/

#------------------------- GENERATE CRACKABLE FUNCTION ----------------------------------------

echo echo ---- GENERATE CRACKABLE FUNCTION ---

#Test generate function without setting output path
./corsair -x 16

#Test generate function setting output path at the end
./corsair -x 16 -o "$dirTestResOut"xFunc01/

#Test generate function setting output path at the start
./corsair  -o "$dirTestResOut"xFunc02/ -x 16


#--------------------- MAIN FUNCTION WITH CRACKABLE GENERATED KEYS -------------------------------

echo echo --- MAIN FUNCTION WITH CRACKABLE GENERATED KEYS ---

#Test corsair main function with standard output path
./corsair -p "$dirTestResOut"xFunc01/

#Test corsair main function with setted output path at the end
./corsair -p "$dirTestResOut"xFunc01/ -o "$dirTestResOut"p_xFunc01/

#Test corsair main function with setted output path at the beggining
./corsair -o ."$dirTestResOut"p_xFunc02/ -p "$dirTestResOut"xFunc01/



#Test corsair main function with standard output path
./corsair -p "$dirTestResOut"xFunc02/

#Test corsair main function with setted output path at the end
./corsair -p "$dirTestResOut"xFunc02/ -o "$dirTestResOut"p_xFunc03/

#Test corsair main function with setted output path at the beggining
./corsair -o ."$dirTestResOut"p_xFunc04/ -p "$dirTestResOut"xFunc02/



#------------------------- GENERATE PRIVATE AND PUBLIC KEYS FUNCTION  (FROM ALGORITHM) ----------------------------------------

echo echo ---- GENERATE PRIVATE AND PUBLIC KEYS FUNCTION  FROM ALGORITHM ---

#Generates a Private and public Key from two Big Nums in String Form:
./corsair -C 171668005736312320838163729952276949982854994415199773193618288867548827965639919410493652712853022122316617758428088247128886690354536714915038974870406560317128022740325354738145914533499826880951735986746064320374657699657389640017872235510897148538622762812562873470945672684855488701689730647941548075157 140475930401500496299033227376073592513957374789466409611614533193510115385485804618671031646238770587450949615868649317352271163989937507134019778215900891156904323325312273509229976889368765557901489364359229830146882049111224527121650805096088466207983336985717339536941332815164618665653689103167521230319


#Generates a Private and public Key from two Big Nums in String Form with output at the end
./corsair -C 171668005736312320838163729952276949982854994415199773193618288867548827965639919410493652712853022122316617758428088247128886690354536714915038974870406560317128022740325354738145914533499826880951735986746064320374657699657389640017872235510897148538622762812562873470945672684855488701689730647941548075157 140475930401500496299033227376073592513957374789466409611614533193510115385485804618671031646238770587450949615868649317352271163989937507134019778215900891156904323325312273509229976889368765557901489364359229830146882049111224527121650805096088466207983336985717339536941332815164618665653689103167521230319 -o "$dirTestResOut"cFunc01/

#Generates a Private and public Key from two Big Nums in String Form wit output at the start
./corsair -o "$dirTestResOut"cFunc02/ -C 171668005736312320838163729952276949982854994415199773193618288867548827965639919410493652712853022122316617758428088247128886690354536714915038974870406560317128022740325354738145914533499826880951735986746064320374657699657389640017872235510897148538622762812562873470945672684855488701689730647941548075157 140475930401500496299033227376073592513957374789466409611614533193510115385485804618671031646238770587450949615868649317352271163989937507134019778215900891156904323325312273509229976889368765557901489364359229830146882049111224527121650805096088466207983336985717339536941332815164618665653689103167521230319

#Check coherence private keys:

openssl rsa -check -in "$dirTestResOut"cFunc01/*private*
openssl rsa -check -in "$dirTestResOut"cFunc02/*private*

#------------------------- DECRYPT FUNCTION ----------------------------------------
# - Tries to decrypt a bin file with an private key file:
#ToDo

echo echo ---- DECRYPT FUNCTION -----

#Test decrypt function with private key and encrypted message (standard output)
./corsair -d ./Sources/decryptFunc/29_privateKey.pem ./Sources/decryptFunc/29.bin
./corsair -d ./Sources/decryptFunc/82_privateKey.pem ./Sources/decryptFunc/82.bin

#Test decrypt function with private key and encrypted message (setted output at the end)
./corsair -d ./Sources/decryptFunc/29_privateKey.pem ./Sources/decryptFunc/29.bin -o "$dirTestResOut"dFunc01/

#Test decrypt function with private key and encrypted message (setted output at the START)
./corsair -o "$dirTestResOut"dFunc02/ -d ./Sources/decryptFunc/29_privateKey.pem ./Sources/decryptFunc/29.bin


#------------------------- ENCRYPT FUNCTION ----------------------------------------
# - Tries to encrypt a txt file with an public key file:

echo echo ---- ENCRYPT FUNCTION ----

#Encrypts contents of encryptText.txt using public RSA key contained into file publicKey_01.pem 
./corsair -e ./Sources/encryptFunc/publicKey_01.pem ./Sources/encryptFunc/encryptText.txt -o "$dirTestResOut"eFunc01/

#------------------------- TEST PREVIOUS STEP DECRYPTING CONTENT ----------------------------------------

echo echo --- TEST PREVIOUS STEP DECRYPTING CONTENT ---
# - Tries to decrypt the previous encrypted bin file using the private RSA key:
./corsair -d ./Sources/encryptFunc/privateKey_01.pem "$dirTestResOut"eFunc01/*.bin -o "$dirTestResOut"d_eFunc01/

#rm -r ./ouputCTets3/

dirCTest="$dirTestResOut"CTestFunc01/ 

#Generates a Private and public Key from two Big Nums in String Form wit output at the start
./corsair -o "$dirCTest" -C 171668005736312320838163729952276949982854994415199773193618288867548827965639919410493652712853022122316617758428088247128886690354536714915038974870406560317128022740325354738145914533499826880951735986746064320374657699657389640017872235510897148538622762812562873470945672684855488701689730647941548075157 140475930401500496299033227376073592513957374789466409611614533193510115385485804618671031646238770587450949615868649317352271163989937507134019778215900891156904323325312273509229976889368765557901489364359229830146882049111224527121650805096088466207983336985717339536941332815164618665653689103167521230319

echo "my Text to Decrypt number 123456" > "$dirCTest"encryptText.txt

mv "$dirCTest"*private* "$dirCTest"privateKey_01.pem
mv "$dirCTest"*public* "$dirCTest"publicKey_01.pem

#Encrypts contents of encryptText.txt using public RSA key contained into file publicKey_01.pem 
./corsair -e "$dirCTest"publicKey_01.pem "$dirCTest"encryptText.txt -o  "$dirCTest"

# - Tries to decrypt the previous encrypted bin file using the private RSA key:
./corsair -d "$dirCTest"privateKey_01.pem "$dirCTest"encryptText.bin -o "$dirCTest"

#----------------------------------OPEN SSL COMMANDS-----------------------------------------

#openssl rsa -pubout -in privateKey_01.pem -out osslPublicKey_01.pem
#openssl rsa -check -in privateKey_01.pem

