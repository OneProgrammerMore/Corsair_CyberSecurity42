compile-production:
	gcc ./source/corsair.c -o ./binaries/corsair -lm -lssl -lcrypto -w
compile-debug:
	gcc -o ./binaries/corsair -std=c11 -Wall -ggdb3 ./source/corsair.c -lssl -lcrypto -w -lm
test:
	chmod u+x ./tests/corsairTest.sh && ./tests/corsairTest.sh 
leaks-test:
	chmod u+x ./tests/testLeaks.sh && ./tests/testLeaks.sh
clang:
	clang-format -i ./source/corsair.c
astyle:
	astyle --style=google ./source/corsair.c
cppcheck:
	cppcheck --enable=all --inconclusive --std=c99 ./source/corsair.c
flawfinder:
	flawfinder ./source/corsair.c
splint:
	splint ./source/corsair.c
saniteze:
	clang -fsanitize=address,undefined -g ./source/corsair.c -o ./binaries/corsair_sant.c




	
