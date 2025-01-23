#!/bin/bash
#------------------------------ X GENERATE CRACKABLE KEYS --------------------------------
valgrind --log-file=Xout01.file --leak-check=yes --tool=memcheck ./corsair -x  4 -o ./valXOut01/
valgrind --log-file=XTout01.file --leak-check=yes  --track-origins=yes --tool=memcheck ./corsair -x  4 -o ./valXOut02/

#------------------------------ P CRACK KEYS IN PATH --------------------------------
valgrind --log-file=Pout01.file --leak-check=yes --tool=memcheck ./corsair -p ./valXOut01/ -o ./valPOut01/
valgrind --log-file=PTout01.file --leak-check=yes  --track-origins=yes --tool=memcheck ./corsair -p ./valXOut01/ -o ./valPOut02/


#------------------------------ G GENERATE N NOT CRACKABLE KEYS  --------------------------------
valgrind --log-file=Gout01.file --leak-check=yes --tool=memcheck ./corsair -g 5 -o ./valGOut01/
valgrind --log-file=GTout01.file --leak-check=yes  --track-origins=yes --tool=memcheck ./corsair -g 5 -o ./valGOut02/



#------------------------------ C GENERATE KEY FROM BIGNUM --------------------------------
valgrind --log-file=Cout01.file --leak-check=yes --tool=memcheck ./corsair -o ./valCOut01/ \
 -C 171668005736312320838163729952276949982854994415199773193618288867548827965639919410493652712853022122316617758428088247128886690354536714915038974870406560317128022740325354738145914533499826880951735986746064320374657699657389640017872235510897148538622762812562873470945672684855488701689730647941548075157 \
 140475930401500496299033227376073592513957374789466409611614533193510115385485804618671031646238770587450949615868649317352271163989937507134019778215900891156904323325312273509229976889368765557901489364359229830146882049111224527121650805096088466207983336985717339536941332815164618665653689103167521230319


valgrind --log-file=CTout01.file --leak-check=yes  --track-origins=yes --tool=memcheck ./corsair  -o ./valCOut02/ \
 -C 171668005736312320838163729952276949982854994415199773193618288867548827965639919410493652712853022122316617758428088247128886690354536714915038974870406560317128022740325354738145914533499826880951735986746064320374657699657389640017872235510897148538622762812562873470945672684855488701689730647941548075157 \
 140475930401500496299033227376073592513957374789466409611614533193510115385485804618671031646238770587450949615868649317352271163989937507134019778215900891156904323325312273509229976889368765557901489364359229830146882049111224527121650805096088466207983336985717339536941332815164618665653689103167521230319


#------------------------------ E ENCRYPT TEXT --------------------------------

valgrind --log-file=Eout01.file --leak-check=yes --tool=memcheck  \
./corsair -e ./Sources/encryptFunc/publicKey_01.pem ./Sources/encryptFunc/encryptText.txt -o ./Sources/encryptFunc/

valgrind --log-file=ETout01.file --leak-check=yes  --track-origins=yes --tool=memcheck  \
./corsair -e ./Sources/encryptFunc/publicKey_01.pem ./Sources/encryptFunc/encryptText.txt -o ./Sources/encryptFunc/

#------------------------------ D DECRYPT BIN --------------------------------

valgrind --log-file=Dout01.file --leak-check=yes --tool=memcheck  \
./corsair -d ./Sources/decryptFunc/29_privateKey.pem ./Sources/decryptFunc/29.bin

valgrind --log-file=DTout01.file --leak-check=yes  --track-origins=yes --tool=memcheck  \
./corsair -d ./Sources/decryptFunc/29_privateKey.pem ./Sources/decryptFunc/29.bin


#------------------------------ F CRACK KEYS IN FILES --------------------------------

valgrind --log-file=Fout01.file --leak-check=yes --tool=memcheck  \
./corsair -f ./Sources/challenge_corsair/29.pem ./Sources/challenge_corsair/82.pem ./Sources/challenge_corsair/29.bin ./Sources/challenge_corsair/82.bin -o ./fileOutputStart/


valgrind --log-file=FTout01.file --leak-check=yes  --track-origins=yes --tool=memcheck  \
./corsair -f ./Sources/challenge_corsair/29.pem ./Sources/challenge_corsair/82.pem ./Sources/challenge_corsair/29.bin ./Sources/challenge_corsair/82.bin -o ./fileOutputStart/
