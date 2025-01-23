#!/bin/sh

#Call test as 
#./corsairTest.sh | grep -C 4 -E "echo|error|fault"
#Or better:
#./corsairTest.sh | grep -e echo -e error -e fault
#Note: Some warnigns/errors may appear as the program creates the directories.

#Change following var to change output dir
#dirTestRes="results/testRes08/"
#dirValResOut="./valgrindRes08/"
#dirTestResOut="../""$dirTestRes"
#Configuration Variables:
dirTestResOut="./../testsResults/restRes08/"
dirExamplesPath="./../examples/challenge_corsair/"
dirExamplesDecryptFunc="./../examples/decryptFunc/"
dirExampleEncryptFunc="./../examples/encryptFunc/"
corsairBin="./../binaries/corsair"

mkdir -p $dirTestResOut

#--------------------------- HELP FUNCTION ---------------------------------------

echo echo ----- HELP FUNCTION ---

#Help function alone:
$corsairBin -h

#Help Function with other parameters at the end:
$corsairBin -h -p "$dirExamplesPath"
$corsairBin -h -g 10

#Help Function with other parameters at the start:
$corsairBin -g 10 -h


#--------------------------- MAIN FUNCTION ---------------------------------------

echo echo ---- MAIN FUNCTION ------

#Test corsair main function with standard output path
$corsairBin -p "$dirExamplesPath"

#Test corsair main function with setted output path at the end
$corsairBin -p "$dirExamplesPath" -o "$dirTestResOut"pFunc01/
#"$(realpath --relative-to=. "$dirTestResOut")"

#Test corsair main function with setted output path at the beggining
$corsairBin -o "$dirTestResOut"pFunc01/ -p "$dirExamplesPath" 

#------------------------- FILES FUNCTION ----------------------------------------

echo echo ---- FILES FUNCTION -----

#Test file function without setting output path:
$corsairBin -f "$dirExamplesPath"29.pem "$dirExamplesPath"82.pem "$dirExamplesPath"29.bin "$dirExamplesPath"82.bin

#Test file function setting output path at the end:
$corsairBin -f "$dirExamplesPath"29.pem "$dirExamplesPath"82.pem "$dirExamplesPath"29.bin "$dirExamplesPath"82.bin -o "$dirTestResOut"fFunc01/

#Test file function setting output path at the start:
$corsairBin -f "$dirExamplesPath"29.pem "$dirExamplesPath"82.pem "$dirExamplesPath"29.bin "$dirExamplesPath"82.bin -o "$dirTestResOut"fFunc02/

#------------------------- GENERATE FUNCTION ----------------------------------------

echo echo --- GENERATE FUNCTION ----

#Test generate function without setting output path
$corsairBin -g 10

#Test generate function setting output path at the end
$corsairBin -g 10  -o "$dirTestResOut"gFfunc01/

#Test generate function setting output path at the start
$corsairBin  -o "$dirTestResOut"gFfunc02/ -g 10


#--------------------- MAIN FUNCTION WITH GENERATED KEYS -------------------------------

echo echo -- MAIN FUNCTION WITH GENERATED KEYS --

#Test corsair main function with standard output path
$corsairBin -p "$dirTestResOut"gFfunc01/

#Test corsair main function with setted output path at the end
$corsairBin -p "$dirTestResOut"gFfunc01/ -o "$dirTestResOut"p_gFunc01/

#Test corsair main function with setted output path at the beggining
$corsairBin -o "$dirTestResOut"p_gFunc02/ -p "$dirTestResOut"gFfunc01/

#Test corsair main function with standard output path
$corsairBin -p "$dirTestResOut"gFfunc02/

#Test corsair main function with setted output path at the end
$corsairBin -p "$dirTestResOut"gFfunc01/ -o "$dirTestResOut"p_gFunc03/

#Test corsair main function with setted output path at the beggining
$corsairBin -o "$dirTestResOut"p_gFunc04/ -p "$dirTestResOut"gFfunc02/

#------------------------- GENERATE CRACKABLE FUNCTION ----------------------------------------

echo echo ---- GENERATE CRACKABLE FUNCTION ---

#Test generate function without setting output path
$corsairBin -x 16

#Test generate function setting output path at the end
$corsairBin -x 16 -o "$dirTestResOut"xFunc01/

#Test generate function setting output path at the start
$corsairBin  -o "$dirTestResOut"xFunc02/ -x 16


#--------------------- MAIN FUNCTION WITH CRACKABLE GENERATED KEYS -------------------------------

echo echo --- MAIN FUNCTION WITH CRACKABLE GENERATED KEYS ---

#Test corsair main function with standard output path
$corsairBin -p "$dirTestResOut"xFunc01/

#Test corsair main function with setted output path at the end
$corsairBin -p "$dirTestResOut"xFunc01/ -o "$dirTestResOut"p_xFunc01/

#Test corsair main function with setted output path at the beggining
$corsairBin -o ."$dirTestResOut"p_xFunc02/ -p "$dirTestResOut"xFunc01/



#Test corsair main function with standard output path
$corsairBin -p "$dirTestResOut"xFunc02/

#Test corsair main function with setted output path at the end
$corsairBin -p "$dirTestResOut"xFunc02/ -o "$dirTestResOut"p_xFunc03/

#Test corsair main function with setted output path at the beggining
$corsairBin -o ."$dirTestResOut"p_xFunc04/ -p "$dirTestResOut"xFunc02/



#------------------------- GENERATE PRIVATE AND PUBLIC KEYS FUNCTION  (FROM ALGORITHM) ----------------------------------------

echo echo ---- GENERATE PRIVATE AND PUBLIC KEYS FUNCTION  FROM ALGORITHM ---

#Generates a Private and public Key from two Big Nums in String Form:
$corsairBin -C 171668005736312320838163729952276949982854994415199773193618288867548827965639919410493652712853022122316617758428088247128886690354536714915038974870406560317128022740325354738145914533499826880951735986746064320374657699657389640017872235510897148538622762812562873470945672684855488701689730647941548075157 140475930401500496299033227376073592513957374789466409611614533193510115385485804618671031646238770587450949615868649317352271163989937507134019778215900891156904323325312273509229976889368765557901489364359229830146882049111224527121650805096088466207983336985717339536941332815164618665653689103167521230319


#Generates a Private and public Key from two Big Nums in String Form with output at the end
$corsairBin -C 171668005736312320838163729952276949982854994415199773193618288867548827965639919410493652712853022122316617758428088247128886690354536714915038974870406560317128022740325354738145914533499826880951735986746064320374657699657389640017872235510897148538622762812562873470945672684855488701689730647941548075157 140475930401500496299033227376073592513957374789466409611614533193510115385485804618671031646238770587450949615868649317352271163989937507134019778215900891156904323325312273509229976889368765557901489364359229830146882049111224527121650805096088466207983336985717339536941332815164618665653689103167521230319 -o "$dirTestResOut"cFunc01/

#Generates a Private and public Key from two Big Nums in String Form wit output at the start
$corsairBin -o "$dirTestResOut"cFunc02/ -C 171668005736312320838163729952276949982854994415199773193618288867548827965639919410493652712853022122316617758428088247128886690354536714915038974870406560317128022740325354738145914533499826880951735986746064320374657699657389640017872235510897148538622762812562873470945672684855488701689730647941548075157 140475930401500496299033227376073592513957374789466409611614533193510115385485804618671031646238770587450949615868649317352271163989937507134019778215900891156904323325312273509229976889368765557901489364359229830146882049111224527121650805096088466207983336985717339536941332815164618665653689103167521230319

#Check coherence private keys:

openssl rsa -check -in "$dirTestResOut"cFunc01/*private*
openssl rsa -check -in "$dirTestResOut"cFunc02/*private*

#------------------------- DECRYPT FUNCTION ----------------------------------------
# - Tries to decrypt a bin file with an private key file:
#ToDo

echo echo ---- DECRYPT FUNCTION -----

#Test decrypt function with private key and encrypted message (standard output)
$corsairBin -d "$dirExamplesDecryptFunc"29_privateKey.pem "$dirExamplesDecryptFunc"29.bin
$corsairBin -d "$dirExamplesDecryptFunc"82_privateKey.pem "$dirExamplesDecryptFunc"82.bin

#Test decrypt function with private key and encrypted message (setted output at the end)
$corsairBin -d "$dirExamplesDecryptFunc"29_privateKey.pem "$dirExamplesDecryptFunc"29.bin -o "$dirTestResOut"dFunc01/

#Test decrypt function with private key and encrypted message (setted output at the START)
$corsairBin -o "$dirTestResOut"dFunc02/ -d "$dirExamplesDecryptFunc"29_privateKey.pem "$dirExamplesDecryptFunc"29.bin


#------------------------- ENCRYPT FUNCTION ----------------------------------------
# - Tries to encrypt a txt file with an public key file:

echo echo ---- ENCRYPT FUNCTION ----

#Encrypts contents of encryptText.txt using public RSA key contained into file publicKey_01.pem 
$corsairBin -e "$dirExampleEncryptFunc"publicKey_01.pem "$dirExampleEncryptFunc"encryptText.txt -o "$dirTestResOut"eFunc01/

#------------------------- TEST PREVIOUS STEP DECRYPTING CONTENT ----------------------------------------

echo echo --- TEST PREVIOUS STEP DECRYPTING CONTENT ---
# - Tries to decrypt the previous encrypted bin file using the private RSA key:
$corsairBin -d "$dirExampleEncryptFunc"privateKey_01.pem "$dirTestResOut"eFunc01/*.bin -o "$dirTestResOut"d_eFunc01/

#rm -r ./ouputCTets3/

dirCTest="$dirTestResOut"CTestFunc01/ 
mkdir -p "$dirCTest"

#Generates a Private and public Key from two Big Nums in String Form wit output at the start
$corsairBin -o "$dirCTest" -C 171668005736312320838163729952276949982854994415199773193618288867548827965639919410493652712853022122316617758428088247128886690354536714915038974870406560317128022740325354738145914533499826880951735986746064320374657699657389640017872235510897148538622762812562873470945672684855488701689730647941548075157 140475930401500496299033227376073592513957374789466409611614533193510115385485804618671031646238770587450949615868649317352271163989937507134019778215900891156904323325312273509229976889368765557901489364359229830146882049111224527121650805096088466207983336985717339536941332815164618665653689103167521230319

echo "my Text to Decrypt number 123456" > "$dirCTest"encryptText.txt

mv "$dirCTest"*private* "$dirCTest"privateKey_01.pem
mv "$dirCTest"*public* "$dirCTest"publicKey_01.pem

#Encrypts contents of encryptText.txt using public RSA key contained into file publicKey_01.pem 
$corsairBin -e "$dirCTest"publicKey_01.pem "$dirCTest"encryptText.txt -o  "$dirCTest"

# - Tries to decrypt the previous encrypted bin file using the private RSA key:
$corsairBin -d "$dirCTest"privateKey_01.pem "$dirCTest"encryptText.bin -o "$dirCTest"

#----------------------------------OPEN SSL COMMANDS-----------------------------------------

#openssl rsa -pubout -in privateKey_01.pem -out osslPublicKey_01.pem
#openssl rsa -check -in privateKey_01.pem

