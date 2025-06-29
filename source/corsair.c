#include <stdio.h>

// In order to search for files in a folder:
// https://faq.cprogramming.com/cgi-bin/smartfaq.cgi?answer=1046380353&id=1044780608
#include <dirent.h>

// In order to compare strings:
#include <libgen.h>
#include <string.h>

#include <assert.h>
#include <errno.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <stdlib.h>

// For OSSL_PARAM
#include <openssl/core.h>
#include <openssl/decoder.h>
#include <openssl/ec.h>
#include <openssl/encoder.h>
#include <openssl/engine.h>
#include <openssl/param_build.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <time.h>
// In order to use ceil function
#include <math.h>

void getNandEFromFile(const BIGNUM **resN, const BIGNUM **resE,
		      char *inputFile);
int file_exists(const char *pathname);
int dir_exists(const char *dirname);

struct userInputCorsair {

	int wrongUserInputBool; // Determines if the user input in terminal is
				// correct or not (correct = 0, incorrect >0)

	int helpBool; // Determines if -f is set in order to print help

	int pFuncBool;	  // Determines if the pFunc is called (-p flag)
	char pPath[2500]; // The path for the -p flag opiton will be here stored

	int fFuncBool; // Determines if the fFunc is called (-f flag)
	char pemFileOne4fFunc[2500]; // path for pem file One for function -f
	char pemFileTwo4fFunc[2500]; // path for pem file One for function -f
	char binFileOne4fFunc[2500]; // path for bin file One for function -f
	char binFileTwo4fFunc[2500]; // path for pem file One for function -f

	int cFuncBool; // Determines if -C function is called (-c flag)
	char BN_One_cFunc[3000]; // The string corresponding to the first Bignum
				 // will be saved here
	char BN_Two_cFunc[3000]; // The string corresponding to the two Bignum
				 // will be saved here

	int xFuncBool;	  // Determines if X function is called (flag -x)
	int number_xFunc; // Determines the number of files to create (Cannot be
			  // 0)

	int gFuncBool;	  // Determines if g function is called (flag -g)
	int number_gFunc; // Determines N for g function (number of keys to
			  // create)

	int dFuncBool;
	char dPrivateKeyFile[2500];
	char dBinFile[2500];

	int outputPathBool;    // Determines if a output path is given (flag -o)
	char outputPath[2500]; // The output path will be saved here
	char outputPathAbs[3000];
	char currentDir[3000];

	// For encryption function
	int eFuncBool;
	char eEncryptPublicKey[2500];
	char eEncryptTextFile[2500];
};

typedef struct userInputCorsair UserInputCorsair;

void CrackPrivateKeyFromPublicKeysFinal(UserInputCorsair *mainInput);

const char helpStrGlobal[] =
    "corsair is a program used to crack RSA passwords and work with RSA keys. \n\
\n\
The capabilities of this program are the following: \n\
\n\
 -h      --> Prints the Program help.\n\
  \n\
 -p (path)   --> The main function. Reads all .pem files in the -p path and tries to crack the private password with other .pem files in the folder. If the provate key is cracked it decodes the .bin file \n\
              with equal name as the private key '.pem' file1\n\
              Example of files in the folder\n\
                1.pem\n\
                2.pem \n\
                1.bin\n\
                2.bin\n\
              If the key of '1.pem' and '2.pem' was cracked, the program decrypts the files 2.bin and 2.bin.\n\
              It also generates a .pem file for each public key cracked with the respective private key.\n\
              This file will be named after the file containing the public key, the key type, the program name and the version of the program used.\n\
              As example if 1.pem and 2.pem files containing a public key where cracked, two files will be created containing the private key. \n\
              Those files will be named for corsair version 0.001:\n\
                1_privateKey_Corsair_0-001.pem\n\
                2_privateKey_Corsair_0-001.pem\n\
              The function also saves the decoded message in .txt files, which will be named as:\n\
                1_decryptedMessage_Corsair_0-001.txt\n\
                2_decryptedMessage_Corsair_0-001.txt\n\
   \n\
 -f (file1.pem file2.pem file1.bin file2.bin)  --> The flag -f does the same as the flag -p but for 4 specific files. It does not read recursively a path looking for files to crack.\n\
                                                    This flag allows working with files which are not named for the use of the function used for -p\n\
                                                    It creates the same files as the function used with the -p flag (if key was cracked)\n\
\n\
\n\
 -g (N) 	--> Generate N 'YES Random' public keys, private keys and encrypted messages in order to check the functionability of the -d path function.\n\
\n\
\n\
 - FOR VERSION 0.002 \n\n\
  -C ('BIGNUM IN ASCII' 'BIGNUM IN ASCII')-C ('BIGNUM IN ASCII' 'BIGNUM IN ASCII')       --> The flag C calculate the RSA keys for the two BIGNUMs give in ASCII format and generates 2 key .pem files. One for the public key\n\
                                                      and other for the private key.\n\
                                                      Remember that the numbers need to:\n\
                                                        1. Be integers (No Float are allowed)\n\
                                                        2. Be Primes\n\
                                                        3. Not be the same number\n\
                                                    \n\
  -o (outputPath)                                 --> Specifies the ouput path where the output files will be stored. If not output path is specified the relative path './CorsairOutputV0-001/' will be used\n\
                                                     [WARNING] The program creates the path if it does NOT exist, but does NOT check for file 'collision'. Therefore some files in the ouput folder could be deleted.    \n\
                                                    \n\
 -h   	--> Show the help of the program into terminal.\n\
\n\
 -x (N) 	--> Generate N 'NOT Random' public keys, private keys and encrypted messages in order to check the functionability of the -p path function. (USED FOR DEBUGGING and TESTING)\n\
\
\n\
 -d (private_key_file.pem encrypted_file.bin)   --> Tries to decrypt the ecrypted_file.bin using the private key contained into the private_key_file.pem.\n\
                                                      If succes shows the decrypted message into terminal.\n\
                                                      If fails shows error into terminal.\n\
 -e (public_key_file.pem input_text_file.txt)   --> if the length of the text of the input_text_file is lower or equal than the maximum encryption lenght,\n\
													this function encrypts the text and save it into the file given with the -o flag. \n\
";

/*
  ToDo for Version 0.002\n\
  - [x] Input Read Arguments Function With Parameters stored into Struct and
  check consistency of gieven parameters\n\
  - [x] Help Print Function\n\
  - [x] Create Output Folder if needed\n\
  - [  ] -p Function\n\
    - [ ] Clean\n\
    - [ ] Create .pem files and save into output with name public key files\n\
    - [ ] Create .txt files and save into output path with decrypted message\n\
    - [ ] Free all variables\n\
  - [ ] -f Function\n\
    - [ ] SAME as -p but for 4 files\n\
  - [ ] -C function\n\
  - [ ] -x function using the same function as -C\n\
  - [ ] .g function using the same function as -C\n\
  - [ ] -d function \n\

  ToDo for Version 0.002\n\
  - [ ] H (HASH)   --> Specifies the HASH to be used for all functions \n\
  - [ ] F (file.pem) --> Cracks the public key stored into file.pem \n\
  - [ ] Clean Code\n\
  - [ ] Assure all Variables are freedn\n\
  - [ ] All functions with 'no deprecated' open ssl functions\n 
*/

int SetInputUser(int argc, char *argv[], UserInputCorsair *mainInput)
{

	mainInput->wrongUserInputBool = 0;

	// Set the struct variables boolens as the standard:
	// Initialize Variables
	mainInput->wrongUserInputBool = 0;
	mainInput->helpBool = 0;
	mainInput->pFuncBool = 0;
	mainInput->pPath[0] = NULL;
	mainInput->fFuncBool = 0;

	mainInput->pemFileOne4fFunc[0] = NULL;
	mainInput->pemFileTwo4fFunc[0] = NULL;
	mainInput->binFileOne4fFunc[0] = NULL;
	mainInput->binFileTwo4fFunc[0] = NULL; // 10

	mainInput->cFuncBool = 0;
	mainInput->BN_One_cFunc[0] = NULL;
	mainInput->BN_Two_cFunc[0] = NULL;
	mainInput->xFuncBool = 0;
	mainInput->number_xFunc = 0;

	mainInput->gFuncBool = 0;
	mainInput->number_gFunc = 0;
	mainInput->dFuncBool = 0;
	mainInput->dPrivateKeyFile[0] = NULL;
	mainInput->dBinFile[0] = NULL; // 20

	mainInput->outputPathBool = 0;
	mainInput->outputPath[0] = NULL;

	mainInput->currentDir[0] = NULL;

	mainInput->eEncryptPublicKey[0] = NULL;
	mainInput->eEncryptTextFile[0] = NULL;
	mainInput->eFuncBool = 0; // 26

	// Define some variables for the function
	int noMoreFlags = 0;
	int newArgumentExpected = 0;
	int lengthArgAux = 0;
	int FlagExpected = 1;
	int intAux = 1;
	int counterNoFlag = 0;

	char charArgLetter = 'X';

	// Set int index in order to read all arguments
	// It starts with 1 as the first argument in the array is the
	// command/program executed
	int index = 1;
	int indexArg = 1;
	char argLetter;
	// For all elements in list argv startin by 1:
	for (index = 1; index < argc; index++) {
		// If argument starts with - it is a flag
		// Important - for char comparison use '' instead of ""
		if ((argv[index][0] == '-') && (FlagExpected == 1)) {
			counterNoFlag = 0;
			lengthArgAux = strlen(argv[index]);
			indexArg = 1;

			// For all characters of the argument in position
			// [index]
			for (indexArg = 1; indexArg < lengthArgAux;
			     indexArg++) {
				// Find the char in position [indexArg] in order
				// to compare. Equal is allowed because it is
				// not an string, it is just a char
				charArgLetter = argv[index][indexArg];

				if (FlagExpected == 1) {
					// Help -h
					if (charArgLetter == 'h') {

						mainInput->helpBool = 1;
						noMoreFlags = 1;
						newArgumentExpected = 1;
						FlagExpected = 0;

						//-p path
					} else if (charArgLetter == 'p') {
						mainInput->pFuncBool = 1;
						newArgumentExpected = 1;
						FlagExpected = 0;
						//-f file x 4
					} else if (charArgLetter == 'f') {
						mainInput->fFuncBool = 1;
						newArgumentExpected = 1;
						FlagExpected = 0;
						//-C BN BN
					} else if (charArgLetter == 'C') {
						mainInput->cFuncBool = 1;
						newArgumentExpected = 1;
						FlagExpected = 0;
						//-o output path
					} else if (charArgLetter == 'o') {

						mainInput->outputPathBool = 1;
						newArgumentExpected = 1;
						FlagExpected = 0;
						//-x N
					} else if (charArgLetter == 'x') {

						mainInput->xFuncBool = 1;
						newArgumentExpected = 1;
						FlagExpected = 0;
						//-g N
					} else if (charArgLetter == 'g') {
						mainInput->gFuncBool = 1;
						newArgumentExpected = 1;
						FlagExpected = 0;
						//-d file1.pem file1.bin
					} else if (charArgLetter == 'd') {
						mainInput->dFuncBool = 1;
						newArgumentExpected = 1;
						FlagExpected = 0;

					} else if (charArgLetter == 'e') {
						mainInput->eFuncBool = 1;
						newArgumentExpected = 1;
						FlagExpected = 0;

					} else {
						printf("The user input in "
						       "terminal is NOT "
						       "correct.\n");
						printf("The flag = %c is not "
						       "recognized \n",
						       charArgLetter);
						mainInput->wrongUserInputBool =
						    1;
					}
				} else {
					printf("USER INPUT ERROR - A new "
					       "argument was/is expected afer "
					       "the flag = %c\n",
					       charArgLetter);
					mainInput->wrongUserInputBool = 1;
				}
			}

		} else {

			// help
			if (charArgLetter == 'h') {

				mainInput->wrongUserInputBool = 1;
				noMoreFlags = 1;
				newArgumentExpected = 1;

				//-p path
			} else if (charArgLetter == 'p') {

				strncpy(mainInput->pPath, argv[index],
					sizeof(mainInput->pPath));
				newArgumentExpected = 0;
				FlagExpected = 1;

				//-f file x 4
			} else if (charArgLetter == 'f') {

				if (counterNoFlag == 0) {

					// Check consistenci of arguments (at
					// least for arguments more given for
					// this flag) Check if 4 or 3
					if ((argc - index) < 4) {
						printf(
						    "Too few files are given "
						    "for the flag = %c \n",
						    charArgLetter);
						mainInput->wrongUserInputBool =
						    1;
					}

					strncpy(
					    mainInput->pemFileOne4fFunc,
					    argv[index],
					    sizeof(
						mainInput->pemFileOne4fFunc));
				} else if (counterNoFlag == 1) {
					strncpy(
					    mainInput->pemFileTwo4fFunc,
					    argv[index],
					    sizeof(
						mainInput->pemFileTwo4fFunc));
				} else if (counterNoFlag == 2) {
					strncpy(
					    mainInput->binFileOne4fFunc,
					    argv[index],
					    sizeof(
						mainInput->binFileOne4fFunc));
				} else if (counterNoFlag == 3) {
					strncpy(
					    mainInput->binFileTwo4fFunc,
					    argv[index],
					    sizeof(
						mainInput->binFileTwo4fFunc));
					noMoreFlags = 0;
					FlagExpected = 1;
				} else {
					printf("To many arguments for the flag "
					       "= %c \n",
					       charArgLetter);
					mainInput->wrongUserInputBool = 1;
				}

				newArgumentExpected = 0;

				//-C BN BN
			} else if (charArgLetter == 'C') {

				if (counterNoFlag == 0) {

					// Check consistenci of arguments (at
					// least for arguments more given for
					// this flag)
					if ((argc - index) < 2) {
						printf(
						    "Too few files are given "
						    "for the flag = %c \n",
						    charArgLetter);
						mainInput->wrongUserInputBool =
						    1;
					}

					strncpy(
					    mainInput->BN_One_cFunc,
					    argv[index],
					    sizeof(mainInput->BN_One_cFunc));

				} else if (counterNoFlag == 1) {
					strncpy(
					    mainInput->BN_Two_cFunc,
					    argv[index],
					    sizeof(mainInput->BN_Two_cFunc));
					noMoreFlags = 0;
					FlagExpected = 1;
				} else {
					printf("To many arguments for the flag "
					       "= %c \n",
					       charArgLetter);
					mainInput->wrongUserInputBool = 1;
				}

				newArgumentExpected = 1;
				//-o output path
			} else if (charArgLetter == 'o') {

				strncpy(mainInput->outputPath, argv[index],
					sizeof(mainInput->outputPath));
				noMoreFlags = 0;
				newArgumentExpected = 1;
				FlagExpected = 1;

				//-x N
			} else if (charArgLetter == 'x') {
				intAux = atoi(argv[index]);
				if (intAux > 0) {
					mainInput->number_xFunc = intAux;
					FlagExpected = 1;
				} else {
					printf("The argument given for the "
					       "flag = %c MUST be an Integer "
					       "higher or equal than 1. \n");
					mainInput->wrongUserInputBool = 1;
				}

				newArgumentExpected = 1;
				//-g N
			} else if (charArgLetter == 'g') {

				intAux = atoi(argv[index]);
				if (intAux > 0) {
					mainInput->number_gFunc = intAux;
				} else {
					printf("The argument given for the "
					       "flag = %c MUST be an Integer "
					       "higher or equal than 1. \n");
					mainInput->wrongUserInputBool = 1;
				}
				FlagExpected = 1;
				newArgumentExpected = 1;

				//-d file1.pem file1.bin
			} else if (charArgLetter == 'd') {

				if (counterNoFlag == 0) {

					// Check consistenci of arguments (at
					// least for arguments more given for
					// this flag) Check if 1 or 2
					if ((argc - index) < 2) {
						printf("Too few files ae given "
						       "for the flag = %c \n",
						       charArgLetter);
						mainInput->wrongUserInputBool =
						    1;
					}

					strncpy(
					    mainInput->dPrivateKeyFile,
					    argv[index],
					    sizeof(mainInput->dPrivateKeyFile));
				} else if (counterNoFlag == 1) {
					strncpy(mainInput->dBinFile,
						argv[index],
						sizeof(mainInput->dBinFile));
					noMoreFlags = 0;
					FlagExpected = 1;
				} else {
					printf("To many arguments for the flag "
					       "= %c \n",
					       charArgLetter);
					mainInput->wrongUserInputBool = 1;
				}

				newArgumentExpected = 1;
				//-d file1.pem file1.bin
			} else if (charArgLetter == 'e') {

				if (counterNoFlag == 0) {

					// Check consistenci of arguments (at
					// least for arguments more given for
					// this flag) Check if 1 or 2
					if ((argc - index) < 2) {
						printf("Too few files ae given "
						       "for the flag = %c \n",
						       charArgLetter);
						mainInput->wrongUserInputBool =
						    1;
					}

					strncpy(
					    mainInput->eEncryptPublicKey,
					    argv[index],
					    sizeof(
						mainInput->eEncryptPublicKey));
				} else if (counterNoFlag == 1) {
					strncpy(
					    mainInput->eEncryptTextFile,
					    argv[index],
					    sizeof(
						mainInput->eEncryptTextFile));
					noMoreFlags = 0;
					FlagExpected = 1;
				} else {
					printf("To many arguments for the flag "
					       "= %c \n",
					       charArgLetter);
					mainInput->wrongUserInputBool = 1;
				}

				newArgumentExpected = 1;

			} else {
				printf("The user input in terminal is NOT "
				       "correct. \n");
				printf("The flag = %c is not recognized \n",
				       charArgLetter);
				mainInput->wrongUserInputBool = 1;
			}

			counterNoFlag++;
		}
	}

	return 0;
}

int CheckJustNumbers(char *numberString)
{
	int resultBool = 1; // Correct
	char numbers[] = "0123456789";
	int i = 0;
	int n;
	int auxBool = 0;
	for (i = 0; i < strlen(numberString); i++) {
		auxBool = 0;
		for (n = 0; n < sizeof(numbers); n++) {

			if (numberString[i] == numbers[n]) {
				auxBool = 1;
			}
		}
		if (auxBool != 1) {
			return 0;
		}
	}

	return resultBool;
}

int file_exists(const char *filename)
{
	FILE *fp = fopen(filename, "r");
	int is_exist = 0;
	if (fp != NULL) {
		is_exist = 1;
		fclose(fp); // close the file
	}
	return is_exist;
}

int dir_exists(const char *dirname)
{
	DIR *dir = opendir(dirname);
	int is_exist = 0;
	if (dir != NULL) {
		is_exist = 1;
		closedir(dir);
	}
	return is_exist;
}

void CheckIntegrityProgramVariables(UserInputCorsair *mainInput)
{
	/*CheckIntegrityProgramVariables is a function that checks the input
	variables in order to know if they are correct It checks:
	  - If paths and files exists in the system
	  - If BN string are just numbers and Integers
	*/

	int file1Exists = 0;
	int file2Exists = 0;
	int file3Exists = 0;
	int file4Exists = 0;

	if (mainInput->pFuncBool == 1) {
		if (dir_exists(mainInput->pPath) == 0) {
			printf("The given path with the flag optin -p : %s , "
			       "does NOT exists.\n",
			       mainInput->pPath);
			mainInput->wrongUserInputBool = 1;
		}
	}

	if (mainInput->fFuncBool == 1) {

		file1Exists = file_exists(mainInput->pemFileOne4fFunc);
		file2Exists = file_exists(mainInput->pemFileTwo4fFunc);
		file3Exists = file_exists(mainInput->binFileOne4fFunc);
		file4Exists = file_exists(mainInput->binFileTwo4fFunc);

		if (file1Exists == 0 || file2Exists == 0 || file3Exists == 0 ||
		    file4Exists == 0) {
			printf("Some or all of the given files with the flag "
			       "optin -f , do NOT exists.\n");
			mainInput->wrongUserInputBool = 1;
		}
	}

	int numberRight1 = 0;
	int numberRight2 = 0;

	if (mainInput->cFuncBool == 1) {

		numberRight1 = CheckJustNumbers(mainInput->BN_One_cFunc);
		numberRight2 = CheckJustNumbers(mainInput->BN_Two_cFunc);

		if (numberRight1 == 0 || numberRight2 == 0) {
			printf("Some of the numbers given to the function with "
			       "flag -c contain no number ASCII characters.\n");
			printf("Just the characters contained in the following "
			       "string are accepted: 1234567890\n");
			mainInput->wrongUserInputBool = 1;
		}
	}

	if (mainInput->xFuncBool == 1) {
		if (mainInput->number_xFunc < 1) {
			printf("The number given to the function with flag -x "
			       "must be higher than 0\n");
			mainInput->wrongUserInputBool = 1;
		}
	}

	if (mainInput->gFuncBool == 1) {
		if (mainInput->number_gFunc < 1) {
			printf("The number given to the function with flag -g "
			       "must be higher than 0\n");
			mainInput->wrongUserInputBool = 1;
		}
	}

	if (mainInput->dFuncBool == 1) {

		file1Exists = file_exists(mainInput->dPrivateKeyFile);
		file2Exists = file_exists(mainInput->dBinFile);

		if (file1Exists == 0 || file2Exists == 0) {
			printf("Some or all of the given files with the flag "
			       "option -d , do NOT exists.\n");
			mainInput->wrongUserInputBool = 1;
		}
	}

	int outputPathBool;    // Determines if a output path is given (flag -o)
	char outputPath[2500]; // The output path will be saved here
	int pathInt = 0;
	int currentDirInt = 0;

	if (getcwd(mainInput->currentDir, sizeof(mainInput->currentDir)) ==
	    NULL) {
		mainInput->wrongUserInputBool = 1;
	} else {
		strncpy(mainInput->outputPathAbs, mainInput->currentDir,
			sizeof(mainInput->outputPathAbs));
	}

	if (mainInput->helpBool == 0) {

		if (mainInput->outputPathBool == 0) {
			printf("No output path is given by the user. Setting "
			       "output path to standard path as "
			       "./CorsairOutputFiles/\n");
			strncpy(mainInput->outputPath, "./CorsairOutputFiles/",
				sizeof(mainInput->outputPath));
		}

		// if ouput path starts by "." -> relative path
		if (mainInput->outputPath[0] == '.') {
			// FixMe - ToDo - Fix For relative paths starting by ../
			strncat(mainInput->outputPathAbs,
				mainInput->outputPath + 1,
				sizeof(mainInput->outputPathAbs));

			// If output path starts with / absolute path
			// Windowwwwsss why are you not workiiing... change /
			// for \\ in windows... bill gates closing doors..
		} else if (mainInput->outputPath[0] == '/') {

			strncpy(mainInput->outputPathAbs, mainInput->outputPath,
				sizeof(mainInput->outputPathAbs));
			printf("Setting path for output as %s \n",
			       mainInput->outputPathAbs);

			// Wrong path
		} else {
			printf("The given path could not be created. Given "
			       "path = %s\n",
			       mainInput->outputPath);
			printf("The given path could not be created. Given "
			       "path = %s\n",
			       mainInput->outputPathAbs);
			mainInput->wrongUserInputBool = 1;
		}

		if (dir_exists(mainInput->outputPathAbs) == 1) {
			printf("The output path already exists. WARNING - Some "
			       "files could be removed by the program if names "
			       "are equal.\n");
		} else {
			printf("The selected path %s does not exists. "
			       "Therefore it will be created.\n",
			       mainInput->outputPathAbs);
			// Crate path
			pathInt = mkdir(mainInput->outputPathAbs, 0777);
			perror("Warning: \n");
			printf("Dir created: %s\n", mainInput->outputPathAbs);
		}

		if (dir_exists(mainInput->outputPathAbs) == 0) {
			printf("ERROR - The given path could not be created! "
			       "Aborting program!\n");
			printf("The given path could not be created. Given "
			       "path Abs = %s \n",
			       mainInput->outputPathAbs);
			printf("PathInt = %d", pathInt);
			printf("Given path: %s \n", mainInput->outputPathAbs);
			mainInput->wrongUserInputBool = 1;
		}
	}
	// ENDLICHHHH
}

void PrintProgramVariables(UserInputCorsair *structToPrint)
{
	/* Prints Input Variables in console forr debugging*/

	printf("wrongUserInputBool = %d \n", structToPrint->wrongUserInputBool);
	printf("helpBool = %d \n", structToPrint->helpBool);
	printf("pFuncBool = %d \n", structToPrint->pFuncBool);
	printf("pPath = %s \n", structToPrint->pPath);
	printf("fFuncBool = %d \n", structToPrint->fFuncBool);

	printf("pemFileOne4Func = %s \n", structToPrint->pemFileOne4fFunc);
	printf("pemFileTwo4Func = %s \n", structToPrint->pemFileTwo4fFunc);
	printf("binFileOne4fFunc = %s \n", structToPrint->binFileOne4fFunc);
	printf("binFileTwo4fFunc = %s \n", structToPrint->binFileTwo4fFunc);

	printf("cFuncBool = %d \n", structToPrint->cFuncBool);
	printf("BN_One_cFunc = %s \n", structToPrint->BN_One_cFunc);
	printf("BN_Two_cFunc = %s \n", structToPrint->BN_Two_cFunc);
	printf("xFuncBool = %d \n", structToPrint->xFuncBool);
	printf("number_xFunc = %d \n", structToPrint->number_xFunc);

	printf("gFuncBool = %d \n", structToPrint->gFuncBool);
	printf("number_gFunc = %d \n", structToPrint->number_gFunc);

	printf("dFUncBool = %d \n", structToPrint->dFuncBool);
	printf("dPrivateKeyFile = %s  \n", structToPrint->dPrivateKeyFile);
	printf("dBinFile = %s \n", structToPrint->dBinFile);

	printf("eFuncBool = %d \n", structToPrint->eFuncBool);
	printf("eEncryptPublicKey = %s  \n", structToPrint->eEncryptPublicKey);
	printf("eEncryptTextFile = %s \n", structToPrint->eEncryptTextFile);

	printf("outputPathBool = %d\n", structToPrint->outputPathBool);
	printf("OutputPath = %s\n\n", structToPrint->outputPath);
}

void CreateNCrackableRSAKeys(UserInputCorsair *mainInput)
{

	// Strings to Ecnrypt - A bad poem I wrote :)
	char textToEncrypt[12][100] = {
	    "Bite the byte",	      "Cus the sky is far",
	    "Write thorugh the ride", "Cus the time is gonna fly",
	    "Type the unspoken",      "Cus the voices are broken",
	    "Read the unsaid",	      "Cus much voices faded away",
	    "Learn the unknown",      "on the way to grow",
	    "Forget the taught",      "on time of draughts."};

	char listBNs[12][400] = {
	    "155675953427462815406805801231764455525294130991104597804081298801"
	    "232294620212010389298796449837919099056866973723457764097600824039"
	    "439780011434042143800527188815978979513831020523981400913903197794"
	    "807693672352031764748866333823133326904296029069275520240847372375"
	    "765407888803591706810866429593206499159067373",
	    "136736481902004454554622554906064875018778933790144549484598266156"
	    "510393417110746330170106301359662037622328919444366981882786961585"
	    "717979243019787118729303456532547517200888798993848599224241330232"
	    "241721631192036472818852126068945258046797625170330276978093065898"
	    "978936626408010420414304052491164235194189371",
	    "158162103965444262151636378094176175114655465347465478786283355070"
	    "698857079055203610556830563147972117846806157037419963745996350596"
	    "144269753628252983468109224675508279187586288855631806797997126227"
	    "926772915086902240014735343941077252284856828743756376898339726992"
	    "877379358892589997279535629526948347866421981",
	    "172377007342902134991798800574708008001229996195589868575323706535"
	    "197078116066634045858873787488370043975911671644985765268870163814"
	    "380807665247800439195628516163733401103263825279775218869407148518"
	    "022209560614757389631810748354327604801779654262406706052579456614"
	    "384524686240826603559291914632687762523877387",
	    "133353464849634422910837937227740982163122311011858189035480370020"
	    "846166108890163858387880359988175815510905603200278682277469641814"
	    "324309941045124804860394864698589395465948642407511667465112911361"
	    "348166253331345595256584508845555576937252687865590609604389368494"
	    "382302505649394660825302370084417884151308251",
	    "158751932532855576337428051571598389446957658899402047330337462721"
	    "169031779510048280326938258335362385345018042267675952002637951838"
	    "548243719957032563308153169274971905703996426687375920937847306516"
	    "670456692531304000570346077587674024092788017953714856997177096212"
	    "210935417013072384629719507813999385736002929",
	    "141641771034495762547730108611195184924343770036956618047107015840"
	    "958004038529184260731058046761192360962800825826012255229810608139"
	    "682565762984155584573019902877334333336472553448582751876096205800"
	    "562026619751887855411645711079597298052289988668538966582709534813"
	    "679917743849861774368450909066733303358754281",
	    "162474342147143788114422299035555988882914545411271766243804830514"
	    "112435593662250839602122088072601547135068151701676502709247189600"
	    "348970695143157879280662757376116687341934727013762254373506881053"
	    "473057080025233940896291463082038090896026599377467011522351696078"
	    "894999303028818987549272891212876149208168351",
	    "156519922896694165365783510932623071787382560376174606147753424435"
	    "040443835260026812084684295628287986236392275055899256565632716468"
	    "348000598535776871828981135663314598989740227560636935688112113291"
	    "607371795481330727769182579509619616318046999459188530868786782605"
	    "165318635698272036781813521924616331057164531",
	    "168187312524615378866679911108817496394399049359139018448258805506"
	    "330046355116529013910393035470226025874207449483769140277392947287"
	    "512809102740783968789706879288125966822330681329584222526362401256"
	    "016731458523236137987075522167576562498999709642188604142235217549"
	    "795157686077344441618668759870092715066801483",
	    "172923751757878317830836368950725497132883380724396878066275580794"
	    "931191723842912404773623085528064250901553127204634599321760969301"
	    "907103082963480473008801243463955885386338637132668759712213356801"
	    "082334701471675697220726604018723956601082730671628860910491937158"
	    "780901151897190660870828044701404669440795171",
	    "175359377227037515790860012821658403973087779487719213087899618931"
	    "546920418145024887865020850229042419590951602082932134620453290576"
	    "593162113589309847356921927146879489792852405434936183065055184250"
	    "987637760430327234133996856094422143972808349807551140336915996630"
	    "177680994969848269355933215424500270392178389"};

	int indexText;
	int indexBN;
	int rand_max = 32767;
	int randomNum;
	int bitsLength = 2048;
	int bitsStaticNum;
	int resInt;
	double newBNBitsLengthDouble;
	int newBNBitsLengthInt;

	BIGNUM *staticBN = BN_new();
	// Maybe Error
	BIGNUM *newBN = BN_new();

	BN_CTX *auxCTX = BN_CTX_new();
	BN_GENCB *auxGENCB = BN_GENCB_new();

	// Undeclared variables from copy save rsa key and save encrypted file:
	int timeInt;
	char *pathName[5000], pathOutputPrivateKey[5000],
	    pathOutputPublicKey[5000], textFile[5000];

	BIO *bp_private;
	BIO *bp_public;
	int lengthMaxToEncrypt;
	char bufferOneTxt[100];
	int intText;
	size_t sizeOneEncrypted, lengthOneTxt;
	char binFileName[5000], binFileNameAndPath[5000];
	FILE *fileOneBin;
	char *timeStr[200];
	int ret;
	char *toOne;
	char *txtFile[5000];

	char *strAuxStaticNumber[5000];

	const BIGNUM *eRSA;
	const BIGNUM *nRSA;
	const BIGNUM *dRSA;
	char *eStr, *nStr, *dStr;

	char *textToEncryptPointer;

	char *iStr[20];

	srand(time(NULL));

	int i;
	for (i = 0; i < mainInput->number_xFunc; i++) {

		RSA *rsaKey = RSA_new();

		sprintf(iStr, "%d", i);

		// get a random number in rang (0, RAND_MAX)
		randomNum = rand();
		// Get index of text to encrypt in range (0,12)
		indexText = randomNum % 12;

		// get a random number for the static BN to use
		randomNum = rand();
		indexBN = (int)randomNum % 12;

		printf("RAND_MAX = %d     randomNum = %d", RAND_MAX, randomNum);
		printf("indexText = %d     indexBN = %d", indexText, indexBN);

		// Set P -Static NUmber
		memset(strAuxStaticNumber, '\0', sizeof(strAuxStaticNumber));
		strncpy(strAuxStaticNumber, listBNs[indexBN],
			sizeof(listBNs[indexBN]));

		resInt = BN_dec2bn(&staticBN, strAuxStaticNumber);
		bitsStaticNum = BN_num_bits(staticBN);

		newBNBitsLengthDouble =
		    ((double)bitsLength + 1) - (double)bitsStaticNum;
		newBNBitsLengthInt = (int)ceil(newBNBitsLengthDouble);

		resInt = 0;
		int counter = 0;
		while (resInt == 0) {
			// int BN_generate_prime_ex2(BIGNUM *ret, int bits, int
			// safe, const BIGNUM *add, const BIGNUM *rem, BN_GENCB
			// *cb, BN_CTX *ctx); Test and check add if fails resInt
			// = BN_generate_prime_ex2(newBN, newBNBitsLengthInt, 0,
			// NULL, NULL, auxGENCB, auxCTX);
			resInt = BN_generate_prime_ex(newBN, newBNBitsLengthInt,
						      1, NULL, NULL, NULL);

			if (resInt != 1 && counter == 0) {
				printf("ERROR - While generating random "
				       "Bignumber! resint = %d\n",
				       resInt);
				printf("INFO - newBNBitsLengthInt = %d\n",
				       newBNBitsLengthInt);
				counter++;
			}
		}

		// resInt = BN_dec2bn(&newBN, strAuxStaticNumber);
		bitsStaticNum = BN_num_bits(newBN);

		// Create Key from 2 BNs Function
		// Edit function in order to (with other name as
		// CreateKeyFrom2BNsAndReturnRSA)
		// CreateKeyFrom2BNsAndReturnRSA(qBN, pBN, **rsaKey) - return
		// RSA Key created Q, P, rsaKey
		CreateKeyFrom2BNsAndReturnRSA(staticBN, newBN, &rsaKey);

		// Check values of rsaKey to coherence:
		// nRSA = RSA_get0_n((const RSA*)rsaKey);
		nRSA = RSA_get0_n(rsaKey);
		if (nRSA == NULL) {
			printf("ERROR - eRSA is NULL\n");
		} else {
			nStr = BN_bn2dec(nRSA);
			printf("n RSA = %s \n", nStr);
		}

		eRSA = RSA_get0_e(rsaKey);
		if (eRSA == NULL) {
			printf("ERROR - nRSA is NULL\n");
		} else {
			eStr = BN_bn2dec(eRSA);
			printf("e RSA = %s \n", eStr);
		}

		dRSA = RSA_get0_d(rsaKey);
		if (dRSA == NULL) {
			printf("ERROR - dRSA is NULL\n");
		} else {
			dStr = BN_bn2dec(dRSA);
			printf("d RSA = %s \n", dStr);
		}

		// Create Name and file and store private key, pulic key and bin
		// file using previous rsa Save private and public RSA Keys with
		// timestamp
		timeInt = (int)time(NULL);

		sprintf(timeStr, "%d", timeInt);

		strncpy(pathName, timeStr, sizeof(timeStr));

		strncpy(pathOutputPrivateKey, mainInput->outputPath,
			sizeof(mainInput->outputPath));
		strncat(pathOutputPrivateKey, pathName, sizeof(pathName));
		strncat(pathOutputPrivateKey, iStr, sizeof(iStr));
		strcat(pathOutputPrivateKey, "-privateKey.pem");

		strncpy(pathOutputPublicKey, mainInput->outputPath,
			sizeof(mainInput->outputPath));
		strncat(pathOutputPublicKey, pathName, sizeof(pathName));
		strncat(pathOutputPublicKey, iStr, sizeof(iStr));
		// strncat(pathOutputPublicKey, "-publicKey.pem",
		// sizeof(pathOutputPublicKey));
		strcat(pathOutputPublicKey, "-publicKey.pem");

		printf("Saving private key into file %s \n",
		       pathOutputPrivateKey);
		bp_private = BIO_new_file(pathOutputPrivateKey, "w+");

		ret = PEM_write_bio_RSAPrivateKey(bp_private, rsaKey, NULL,
						  NULL, 0, NULL, NULL);

		printf("Saving public key in file %s \n", pathOutputPublicKey);
		bp_public = BIO_new_file(pathOutputPublicKey, "w+");

		ret = PEM_write_bio_RSA_PUBKEY(bp_public, rsaKey);

		if (rsaKey != NULL) {
			// Dencrypt
			// Get n from rsa key in order to check that exists:
			lengthMaxToEncrypt = RSA_size(rsaKey);
			toOne = malloc(RSA_size(rsaKey));
			lengthMaxToEncrypt = RSA_size(rsaKey);

			memset(toOne, '\0', lengthMaxToEncrypt);

			memset(bufferOneTxt, '\0', sizeof(bufferOneTxt));
			strncpy(bufferOneTxt, textToEncrypt[indexText],
				strlen(textToEncrypt[indexText]));

			printf("Message to encrypt = %s\n", bufferOneTxt);
			lengthOneTxt = strlen(bufferOneTxt);
			printf("lengthOneTxt = %d\n", lengthOneTxt);

			sizeOneEncrypted = RSA_public_encrypt(
			    lengthOneTxt, bufferOneTxt, toOne, rsaKey,
			    RSA_PKCS1_PADDING);

			// free(textToEncryptPointer);
			printf("Message Encrypted = %.*s \n", sizeOneEncrypted,
			       toOne);
			printf("sizeOneEncrypted = %d\n", sizeOneEncrypted);
			if (sizeOneEncrypted == -1) {
				printf("ERROR - CreateNCrackableRSAKeys - "
				       "sizeOneEncrypted == -1");
				// Error handling:
				ERR_print_errors_fp(stderr);
				// Cleanup and exit

			} else if (sizeOneEncrypted != lengthMaxToEncrypt) {
				printf("ERROR - sizeOneEncrypted != "
				       "lengthMaxToEncrypt");
				printf("ERROR - sizeOneEncrypted = %d\n\n",
				       sizeOneEncrypted);
				// Error handling:
				ERR_print_errors_fp(stderr);
				// Cleanup and exit

			} else {

				// Save in file in output path with name of
				// txtFile changing extension from .txt or las
				// .something to .bin
				changeFileExtToBin(
				    &binFileName, sizeof(binFileName),
				    basename(pathOutputPublicKey));

				printf("sizeof(binFileNameAndPath) = %d\n",
				       sizeof(binFileNameAndPath));
				memset(binFileNameAndPath, '\0',
				       sizeof(binFileNameAndPath));
				strncat(binFileNameAndPath,
					mainInput->outputPath,
					strlen(mainInput->outputPath));
				strncat(binFileNameAndPath, binFileName,
					strlen(binFileName));

				fileOneBin = fopen(binFileNameAndPath, "wb");
				if (fileOneBin == NULL) {
					printf("ERROR - EncryptASCIIFile - "
					       "fileOneBin is NULL!");

				} else {
					fwrite(toOne, 1, sizeOneEncrypted,
					       fileOneBin);
					fclose(fileOneBin);
				}
			}
			free(toOne);
		}

		BIO_free_all(bp_public);
		BIO_free_all(bp_private);

		OPENSSL_free(eStr);
		OPENSSL_free(nStr);
		OPENSSL_free(dStr);

		RSA_free(rsaKey);
	}
	BN_CTX_free(auxCTX);
	BN_GENCB_free(auxGENCB);

	BN_free(staticBN);
	BN_free(newBN);
	return;
}

void CreateKeyFrom2BNsAndReturnRSA(BIGNUM *qBN, BIGNUM *pBN, RSA **rsaKey)
{
	/* The functio CreateKetFrom2BNs generaters a Key from 2 prime BNs
	TODO FOR VERSION 0.002
	*/

	// static const char random_seed_Str[] = "OMG change me if you plan to
	// use me in the future. ERROR - WARNING!!!";

	unsigned long myError;

	char *auxStr;	   // To print Big Number (char buffer)
	char timeStr[200]; // For the name of the keys files
	int timeInt; // To store the time before converting it into an string

	int isPrimeP, isPrimeQ, comparedPQ;
	int resInt;

	BIGNUM *nBN = BN_new();
	BIGNUM *numPMinusBN = BN_new();
	BIGNUM *numQMinusBN = BN_new();
	BIGNUM *phiBN = BN_new();
	BIGNUM *eBN = BN_new();
	BIGNUM *gcd_eAndTotientBN = BN_new();
	BIGNUM *dBN = BN_new();
	BIGNUM *kBN = BN_new();
	BIGNUM *kTimesPhiBN = BN_new();
	BIGNUM *kTimesPhiPlusOneBN = BN_new();
	BIGNUM *kTimesPhiPlusOneDivEBN = BN_new();

	BIGNUM *zeroBN = BN_new(); // Bignum for value 0
	BIGNUM *oneBN = BN_new();  // Bignum for value 1

	resInt = BN_dec2bn(&zeroBN, "0");
	resInt = BN_dec2bn(&oneBN, "1");
	resInt = BN_dec2bn(&kBN, "2");

	char pathOutputPublicKey[3000];
	char pathOutputPrivateKey[3000];
	char pathName[200];
	int ret;

	const BIGNUM *eRSA;
	const BIGNUM *nRSA;
	const BIGNUM *dRSA;

	char *eStr, *nStr, *dStr;

	// Context for BigNum Operations:
	BN_CTX *CTXAux = BN_CTX_new();

	// ALGORITHM Starts!

	// 1. Check if both integers are prime numbers and different
	// https://www.openssl.org/docs/man3.0/man3/BN_generate_prime.html
	isPrimeP = BN_is_prime_ex(pBN, 128, CTXAux, NULL);
	isPrimeQ = BN_is_prime_ex(qBN, 128, CTXAux, NULL);
	// myError =  ERR_get_error();
	// printf("MyError =  %d", myError);
	// https://man.openbsd.org/BN_cmp.3

	comparedPQ = BN_cmp(pBN, qBN);

	if (isPrimeP == 1 && isPrimeQ == 1 && comparedPQ != 0) {
		printf("\nThe conditions are satisfied. isPrimeP = %i , "
		       "isPrimeQ = %i , comparedPQ = %i\n",
		       isPrimeP, isPrimeQ, comparedPQ);
	} else {
		printf("\nThe conditions are NOT satisfied. isPrimeP = %i , "
		       "isPrimeQ = %i , comparedPQ = %i\n",
		       isPrimeP, isPrimeQ, comparedPQ);

		auxStr = BN_bn2dec(pBN);
		printf("P = %s \n", auxStr);
		auxStr = BN_bn2dec(qBN);
		printf("Q = %s \n", auxStr);
		return;
	}

	// 2. Calculate N = p * q
	resInt = BN_mul(nBN, pBN, qBN, CTXAux);

	// 3. Compute the Carmichael's totient function of the product as λ(n) =
	// lcm(p − 1, q − 1) giving phi = (p - 1) * (q - 1);
	resInt = BN_sub(numPMinusBN, pBN, oneBN);
	resInt = BN_sub(numQMinusBN, qBN, oneBN);
	resInt = BN_mul(phiBN, numPMinusBN, numQMinusBN, CTXAux);

	resInt = BN_dec2bn(&eBN, "2");
	// Returns -1 if A (multTotientBG) is smaller than B
	while (BN_cmp(eBN, phiBN) == -1) {

		BN_gcd(gcd_eAndTotientBN, eBN, phiBN, CTXAux);

		if (BN_cmp(gcd_eAndTotientBN, oneBN) == 0) {
			break;
		} else {
			BN_add(eBN, eBN, oneBN);
		}
	}

	// Values missing:
	// k = 2
	/*
	// d = (1 + (k * phi)) / e;
	//(k * phi)
	resInt = BN_mul(kTimesPhiBN, kBN, phiBN, CTXAux);
	//(1 + (k * phi))
	resInt = BN_add(kTimesPhiPlusOneBN, kTimesPhiBN, oneBN);
	//d = (1 + (k * phi)) / e;
	resInt = BN_div(dBN, NULL, kTimesPhiPlusOneBN, eBN, CTXAux);
	//NEW END
	*/

	// Calculate the inverse mod in order to obtain d
	//(e*d)mod T = 1
	// BIGNUM *BN_mod_inverse(BIGNUM *r, BIGNUM *a, const BIGNUM *n, BN_CTX
	// *ctx);

	resInt = BN_mod_inverse(dBN, eBN, phiBN, CTXAux);

	// 6. Public key is n/N and e, and it is used to encrypt
	//  N --> multTotientBG
	//  e --> eBN
	auxStr = BN_bn2dec(nBN);
	printf("\nN = %s \n", auxStr);
	OPENSSL_free(auxStr);
	auxStr = BN_bn2dec(eBN);
	printf("e = %s \n", auxStr);
	OPENSSL_free(auxStr);

	// 7. Private key is n/N and d, and it is used for decryption
	//  N --> nBN
	//  d --> dBN
	auxStr = BN_bn2dec(nBN);
	printf("N = %s \n", auxStr);
	OPENSSL_free(auxStr);
	auxStr = BN_bn2dec(dBN);
	printf("d = %s \n", auxStr);
	OPENSSL_free(auxStr);

	// Create a private key and a public key pem files:
	// int RSA_set0_key(RSA *r, BIGNUM *n, BIGNUM *e, BIGNUM *d);
	ret = RSA_set0_key(*rsaKey, BN_dup(nBN), BN_dup(eBN), BN_dup(dBN));
	// ret = RSA_set0_key(*rsaKey, nBN, eBN, dBN);
	if (ret != 1) {
		printf("Error while setting factors n e and d for rsaOne\n");
	}
	// Other values for the creation of the private key:
	// numPMinusBN -> pMinusOne
	// numQMinusBN -> qMinusOne
	// pBN -> q
	// qBN -> q
	// ret = RSA_set0_factors(rsaKey, BN_dup(pBN), BN_dup(qBN));
	ret = RSA_set0_factors(*rsaKey, BN_dup(pBN), BN_dup(qBN));
	// ret = RSA_set0_factors(*rsaKey, pBN, qBN);
	if (ret != 1) {
		printf("Error while setting factors for rsaOne\n");
	}

	// Set CRT factors
	BIGNUM *dmp1Key = BN_new();
	BIGNUM *dmq1Key = BN_new();
	BIGNUM *iqmpKey = BN_new();
	// dP = (1/e) mod (p-1)
	// dQ = (1/e) mod (q-1)
	// qInv = (1/q) mod p
	ret = BN_mod(dmp1Key, dBN, numPMinusBN, CTXAux);
	ret = BN_mod(dmq1Key, dBN, numQMinusBN, CTXAux);
	ret = BN_mod_inverse(iqmpKey, qBN, pBN, CTXAux);

	ret = RSA_set0_crt_params(*rsaKey, BN_dup(dmp1Key), BN_dup(dmq1Key),
				  BN_dup(iqmpKey));
	// ret = RSA_set0_crt_params(*rsaKey, dmp1Key, dmq1Key, iqmpKey);
	if (ret != 1) {
		printf(
		    "\n\n Error while setting CRT parameters to rsaKey.\n\n");
	}

	// Get n from rsa key in order to check that exists:
	// TO DEBUG INFO
	eRSA = RSA_get0_e(*rsaKey);
	if (eRSA == NULL) {
		printf("ERROR - eRSA is NULL\n");
	}

	nRSA = RSA_get0_n(*rsaKey);
	if (nRSA == NULL) {
		printf("ERROR - nRSA is NULL\n");
	}

	dRSA = RSA_get0_d(*rsaKey);
	if (dRSA == NULL) {
		printf("ERROR - dRSA is NULL\n");
	}

	eStr = BN_bn2dec(eRSA);
	nStr = BN_bn2dec(nRSA);
	dStr = BN_bn2dec(dRSA);

	printf("n RSA = %s \n", nStr);
	printf("e RSA = %s \n", eStr);
	printf("d RSA = %s \n", dStr);

	OPENSSL_free(eStr);
	OPENSSL_free(nStr);
	OPENSSL_free(dStr);

	BN_free(nBN);
	BN_free(eBN);
	BN_free(dBN);
	// BN_free(pBN); BN_free(qBN);
	BN_free(dmp1Key);
	BN_free(dmq1Key);
	BN_free(iqmpKey);

	BN_CTX_free(CTXAux);

	BN_free(numPMinusBN);
	BN_free(numQMinusBN);
	BN_free(phiBN);
	BN_free(gcd_eAndTotientBN);
	BN_free(kBN);
	BN_free(kTimesPhiBN);
	BN_free(kTimesPhiPlusOneBN);
	BN_free(kTimesPhiPlusOneDivEBN);
	BN_free(zeroBN);
	BN_free(oneBN);

	return;
}

void CreateKeyFrom2BNs(UserInputCorsair *mainInput)
{
	/* The functio CreateKetFrom2BNs generaters a Key from 2 prime BNs
	TODO FOR VERSION 0.002

	*/

	// static const char random_seed_Str[] = "OMG change me if you plan to
	// use me in the future. ERROR - WARNING!!!";

	unsigned long myError;

	char *auxStr;	   // To print Big Number (char buffer)
	char timeStr[200]; // For the name of the keys files
	int timeInt; // To store the time before converting it into an string

	int isPrimeP, isPrimeQ, comparedPQ;
	int resInt;

	BIGNUM *nBN = BN_new();
	BIGNUM *pBN = BN_new();
	BIGNUM *qBN = BN_new();
	BIGNUM *numPMinusBN = BN_new();
	BIGNUM *numQMinusBN = BN_new();
	BIGNUM *phiBN = BN_new();
	BIGNUM *eBN = BN_new();
	BIGNUM *gcd_eAndTotientBN = BN_new();
	BIGNUM *dBN = BN_new();
	BIGNUM *kBN = BN_new();
	BIGNUM *kTimesPhiBN = BN_new();
	BIGNUM *kTimesPhiPlusOneBN = BN_new();
	BIGNUM *kTimesPhiPlusOneDivEBN = BN_new();

	BIGNUM *zeroBN = BN_new(); // Bignum for value 0
	BIGNUM *oneBN = BN_new();  // Bignum for value 1

	RSA *rsaCreated = RSA_new();

	resInt = BN_dec2bn(&zeroBN, "0");
	resInt = BN_dec2bn(&oneBN, "1");
	resInt = BN_dec2bn(&kBN, "2");

	// Define p and q from user input
	BN_dec2bn(&pBN, mainInput->BN_One_cFunc);
	BN_dec2bn(&qBN, mainInput->BN_Two_cFunc);

	char pathOutputPublicKey[3000];
	char pathOutputPrivateKey[3000];
	char pathName[200];
	int ret;

	BIGNUM *eRSA;
	BIGNUM *nRSA;
	BIGNUM *dRSA;

	// Context for BigNum Operations:
	BN_CTX *CTXAux = BN_CTX_new();
	// BIOs to store public and private keys:
	BIO *bp_public = NULL, *bp_private = NULL;

	// ALGORITHM Starts!

	// 1. Check if both integers are prime numbers and different
	// https://www.openssl.org/docs/man3.0/man3/BN_generate_prime.html
	isPrimeP = BN_is_prime_ex(pBN, 64, CTXAux, NULL);
	isPrimeQ = BN_is_prime_ex(qBN, 64, CTXAux, NULL);
	// myError =  ERR_get_error();
	// printf("MyError =  %d", myError);
	// isPrimeP = BN_check_prime(pBN);
	// isPrimeQ = BN_check_prime(qBN);
	// https://man.openbsd.org/BN_cmp.3

	comparedPQ = BN_cmp(pBN, qBN);

	if (isPrimeP == 1 & isPrimeQ == 1 & comparedPQ != 0) {
		printf("\nThe conditions are satisfied. isPrimeP = %i , "
		       "isPrimeQ = %i , comparedPQ = %i\n",
		       isPrimeP, isPrimeQ, comparedPQ);
	} else {
		printf("\nThe conditions are NOT satisfied. isPrimeP = %i , "
		       "isPrimeQ = %i , comparedPQ = %i\n",
		       isPrimeP, isPrimeQ, comparedPQ);
		return;
	}

	// 2. Calculate N = p * q
	resInt = BN_mul(nBN, pBN, qBN, CTXAux);

	// 3. Compute the Carmichael's totient function of the product as λ(n) =
	// lcm(p − 1, q − 1) giving phi = (p - 1) * (q - 1);
	resInt = BN_sub(numPMinusBN, pBN, oneBN);
	resInt = BN_sub(numQMinusBN, qBN, oneBN);
	resInt = BN_mul(phiBN, numPMinusBN, numQMinusBN, CTXAux);

	resInt = BN_dec2bn(&eBN, "2");
	// Returns -1 if A (multTotientBG) is smaller than B
	while (BN_cmp(eBN, phiBN) == -1) {

		BN_gcd(gcd_eAndTotientBN, eBN, phiBN, CTXAux);

		if (BN_cmp(gcd_eAndTotientBN, oneBN) == 0) {
			break;
		} else {
			BN_add(eBN, eBN, oneBN);
		}
	}

	// Values missing:
	// k = 2
	/*
	// d = (1 + (k * phi)) / e;
	//(k * phi)
	resInt = BN_mul(kTimesPhiBN, kBN, phiBN, CTXAux);
	//(1 + (k * phi))
	resInt = BN_add(kTimesPhiPlusOneBN, kTimesPhiBN, oneBN);
	//d = (1 + (k * phi)) / e;
	resInt = BN_div(dBN, NULL, kTimesPhiPlusOneBN, eBN, CTXAux);
	//NEW END
	*/

	// Calculate the inverse mod in order to obtain d
	//(e*d)mod T = 1
	// BIGNUM *BN_mod_inverse(BIGNUM *r, BIGNUM *a, const BIGNUM *n, BN_CTX
	// *ctx);

	resInt = BN_mod_inverse(dBN, eBN, phiBN, CTXAux);

	// 6. Public key is n/N and e, and it is used to encrypt
	//  N --> multTotientBG
	//  e --> eBN
	auxStr = BN_bn2dec(nBN);
	printf("\nN = %s \n", auxStr);
	OPENSSL_free(auxStr);
	auxStr = BN_bn2dec(eBN);
	printf("e = %s \n", auxStr);
	OPENSSL_free(auxStr);
	// 7. Private key is n/N and d, and it is used for decryption
	//  N --> nBN
	//  d --> dBN
	auxStr = BN_bn2dec(nBN);
	printf("N = %s \n", auxStr);
	OPENSSL_free(auxStr);
	auxStr = BN_bn2dec(dBN);
	printf("d = %s \n", auxStr);
	OPENSSL_free(auxStr);

	// Create a private key and a public key pem files:
	// int RSA_set0_key(RSA *r, BIGNUM *n, BIGNUM *e, BIGNUM *d);
	// RSA_set0_key(rsaCreated, nBN, eBN, dBN);
	RSA_set0_key(rsaCreated, BN_dup(nBN), BN_dup(eBN), BN_dup(dBN));

	// Other values for the creation of the private key:
	// numPMinusBN -> pMinusOne
	// numQMinusBN -> qMinusOne
	// pBN -> q
	// qBN -> q
	ret = RSA_set0_factors(rsaCreated, BN_dup(pBN), BN_dup(qBN));
	if (ret != 1) {
		printf("Error while setting factors for rsaOne\n");
	}

	// Set CRT factors
	BIGNUM *dmp1Key = BN_new();
	BIGNUM *dmq1Key = BN_new();
	BIGNUM *iqmpKey = BN_new();
	// dP = (1/e) mod (p-1)
	// dQ = (1/e) mod (q-1)
	// qInv = (1/q) mod p
	ret = BN_mod(dmp1Key, dBN, numPMinusBN, CTXAux);
	ret = BN_mod(dmq1Key, dBN, numQMinusBN, CTXAux);
	ret = BN_mod_inverse(iqmpKey, qBN, pBN, CTXAux);

	ret = RSA_set0_crt_params(rsaCreated, BN_dup(dmp1Key), BN_dup(dmq1Key),
				  BN_dup(iqmpKey));
	if (ret != 1) {
		printf("\n\n Error while setting CRT parameters to "
		       "rsaCreated.\n\n");
	}

	// Save private and public RSA Keys with timestamp
	timeInt = (int)time(NULL);

	snprintf(timeStr, sizeof(timeStr),  "%d", timeInt);

	snprintf(pathName, sizeof(pathName), timeStr, sizeof(pathName));

	strncpy(pathOutputPrivateKey, mainInput->outputPath,
		sizeof(pathOutputPrivateKey));
	strncat(pathOutputPrivateKey, pathName, sizeof(pathOutputPrivateKey));
	strncat(pathOutputPrivateKey, "-privateKey.pem",
		sizeof(pathOutputPrivateKey));

	strncpy(pathOutputPublicKey, mainInput->outputPath,
		sizeof(pathOutputPublicKey));
	strncat(pathOutputPublicKey, pathName, sizeof(pathOutputPublicKey));
	strncat(pathOutputPublicKey, "-publicKey.pem",
		sizeof(pathOutputPublicKey));

	printf("Saving private key into file %s \n", pathOutputPrivateKey);
	bp_private = BIO_new_file(pathOutputPrivateKey, "w+");
	ret = PEM_write_bio_RSAPrivateKey(bp_private, rsaCreated, NULL, NULL, 0,
					  NULL, NULL);

	printf("Saving public key in file %s \n", pathOutputPublicKey);
	bp_public = BIO_new_file(pathOutputPublicKey, "w+");
	ret = PEM_write_bio_RSAPublicKey(bp_public, rsaCreated);

	// Print parameters in console to check if needed
	eRSA = BN_dup(RSA_get0_e(rsaCreated));
	nRSA = BN_dup(RSA_get0_n(rsaCreated));
	dRSA = BN_dup(RSA_get0_d(rsaCreated));

	char *eStr, *nStr, *dStr;

	eStr = BN_bn2dec(eRSA);
	nStr = BN_bn2dec(nRSA);
	dStr = BN_bn2dec(dRSA);

	printf("n RSA One = %s \n", nStr);
	printf("e RSA One = %s \n", eStr);
	printf("d RSA One = %s \n", dStr);
	OPENSSL_free(eStr);
	OPENSSL_free(nStr);
	OPENSSL_free(dStr);

	// START ------------------------------------------------------
	BN_free(nBN);
	BN_free(pBN);
	BN_free(qBN);
	BN_free(numPMinusBN);
	BN_free(numQMinusBN);
	BN_free(phiBN);
	BN_free(eBN);
	BN_free(gcd_eAndTotientBN);
	BN_free(dBN);
	BN_free(kBN);
	BN_free(kTimesPhiBN);
	BN_free(kTimesPhiPlusOneBN);
	BN_free(kTimesPhiPlusOneDivEBN);
	BN_free(zeroBN);
	BN_free(oneBN);

	// ToDo- DUP BN FROM RSA
	RSA_free(rsaCreated);

	BN_free(eRSA);
	BN_free(nRSA);
	BN_free(dRSA);
	BN_free(dmp1Key);
	BN_free(dmq1Key);
	BN_free(iqmpKey);
	BN_CTX_free(CTXAux);
	BIO_free_all(bp_public);
	BIO_free_all(bp_private);

	return;
}

void getNandEFromFile(const BIGNUM **resN, const BIGNUM **resE, char *inputFile)
{
	// Function in order to return N a E from a PEM file with a RSA public
	// KEy
	RSA *rsa = RSA_new();
	BIO *keybio = BIO_new(BIO_s_file());

	BIO_read_filename(keybio, inputFile);
	PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);

	if (rsa != NULL) {
		*resN = BN_dup(RSA_get0_n(rsa));
		*resE = BN_dup(RSA_get0_e(rsa));

	} else {
		printf("ERROR - Not RSA Key in file = %s\n", inputFile);
	}

	// Free all
	BIO_free(keybio);
	RSA_free(rsa);

	return;
}

// https://www.gnu.org/software/gcc/bugs/segfault.html
// gcc corsair.c -o corsair -lssl -lcrypto -v -da -Q
// gdb corsair
// run

void CrackPrivateKeyFromPublicKeysFinal(UserInputCorsair *mainInput)
{
	// p flag function

	const int STR_PATH_LEN = 400;
	const int STR_BN_LEN = 600;

	DIR *dOne;
	DIR *dTwo;
	DIR *dOneBin;
	DIR *dTwoBin;

	FILE *fileOne;
	FILE *fileTwo;
	FILE *fileOneBin;
	FILE *fileTwoBin;

	struct dirent *dirOne;
	struct dirent *dirTwo;
	struct dirent *dirOneBin;
	struct dirent *dirTwoBin;

	char nameOne[STR_PATH_LEN];
	char nameTwo[STR_PATH_LEN];
	char nameOneBin[STR_PATH_LEN];
	char nameTwoBin[STR_PATH_LEN];

	long lengthOneBin, lengthTwoBin;

	char *bufferOneBin, *bufferTwoBin;

	int lenOne, lenTwo, gcdBothInt, gcdCmpInt, unityInt, divOneInt,
	    divTwoInt, obtainDOneInt, obtainDTwoInt, lenOneBin, lenTwoBin;

	const BIGNUM *nOne = NULL;
	const BIGNUM *eOne = NULL;
	const BIGNUM *nTwo = NULL;
	const BIGNUM *eTwo = NULL;

	char *nOneStr, *eOneStr, *nTwoStr, *eTwoStr, *TotientOneStr,
	    *qMinusOneStr, *pMinusBothStr, *qOneStr, *pBothStr, *gcdBNStr,
	    *unityBNStr;

	char namePathOne[STR_PATH_LEN];
	char namePathTwo[STR_PATH_LEN];
	char namePathOneBin[STR_PATH_LEN];
	char namePathTwoBin[STR_PATH_LEN];

	char realOneFileName[STR_PATH_LEN];
	char realOneFileNamePlusPath[STR_PATH_LEN];
	char realTwoFileName[STR_PATH_LEN];
	char realTwoFileNamePlusPath[STR_PATH_LEN];

	char nameOneAux[STR_PATH_LEN];
	char nameOneBinAux[STR_PATH_LEN];
	char nameTwoAux[STR_PATH_LEN];
	char nameTwoBinAux[STR_PATH_LEN];

	size_t sizeLengthOneBin = 0;
	size_t sizeLengthTwoBin = 0;
	size_t secretOneLength = 0;
	size_t secretTwoLength = 0;

	int sizeModulusNOne = 0;
	int sizeModulusNTwo = 0;

	unsigned char *secretBufferOneBin;
	unsigned char *secretBufferTwoBin;

	// COULD Break here  FIXME
	BIGNUM *gcdBN = BN_new();
	// BIGNUM* gcdBN;
	BIGNUM *pBoth;
	BIGNUM *pMinusBoth = BN_new();
	;

	BIGNUM *unityBN = BN_new();

	BN_CTX *CTXAux = BN_CTX_new();

	BIGNUM *qOne = BN_new();
	BIGNUM *qTwo = BN_new();
	BIGNUM *qMinusOne = BN_new();
	BIGNUM *qMinusTwo = BN_new();

	int qMinusOneInt, qMinusTwoInt, pMinusBothInt;
	int totientOneInt, totientTwoInt;

	int counterFile = 0;
	int counterFileOne = 0;
	int counterAux = 0;

	BIGNUM *TotientOne = BN_new();
	BIGNUM *TotientTwo = BN_new();

	BIGNUM *dValueOne = BN_new();
	BIGNUM *dValueTwo = BN_new();

	int nOneSize, eOneSize, dOneSize, nTwoSize, eTwoSize, dTwoSize;

	int myErrorDec, errorAuxInt;

	int validationKeyOne = NULL;
	int validationKeyTwo = NULL;

	int validationEcKeyOne = 0;
	int validationEcKeyTwo = 0;

	unsigned long errorLongAux = 0;
	char *errorBufferAux;
	size_t errorBufferAuxLen;

	ENGINE *myEng = NULL;

	char *keyOneDes;
	char *keyTwoDes;
	BIGNUM *auxBN = BN_new();
	char *auxBNStr;

	const BIGNUM *eRSA = BN_new();
	const BIGNUM *nRSA = BN_new();
	const BIGNUM *dRSA = BN_new();

	char *eStr, *nStr, *dStr;

	FILE *filePrivateKeyOne;
	FILE *fileMessageOne;

	char filePrivateKeyOnePath[4000];
	char filePrivateKeyOnePathPem[4000];
	char filePrivateKeyOneName[1000];
	char fileMessageDecodedPathOne[4000];

	FILE *filePrivateKeyTwo;
	FILE *fileMessageTwo;

	char filePrivateKeyTwoPath[4000];
	char filePrivateKeyTwoPathPem[4000];
	char filePrivateKeyTwoName[1000];
	char fileMessageDecodedPathTwo[4000];

	char *toOne, *toTwo;

	size_t sizeOneDecrypted, sizeTwoDecrypted;

	int ret;

	// int RSA_set0_crt_params(RSA *r, BIGNUM *dmp1, BIGNUM *dmq1, BIGNUM
	// *iqmp);
	BIGNUM *dmp1One = BN_new();
	BIGNUM *dmq1One = BN_new();
	BIGNUM *iqmpOne = BN_new();

	BIGNUM *dmp1Two = BN_new();
	BIGNUM *dmq1Two = BN_new();
	BIGNUM *iqmpTwo = BN_new();

	char *myStr;

	// search for all files with PEM extension at the end:
	// Open dir:
	dOne = opendir(mainInput->pPath);

	// If the object DIR d is not NULL
	if (dOne) {

		// While there is a new file or a new folder:
		while ((dirOne = readdir(dOne)) != NULL) {

			counterAux++;

			memset(nameOne, '\0', sizeof(nameOne));

			memcpy(nameOne, dirOne->d_name, sizeof(nameOne));

			// Initialize name with system path for the file

			memset(namePathOne, '\0', sizeof(namePathOne));
			strncat(namePathOne, mainInput->pPath,
				sizeof(namePathOne));
			strncat(namePathOne, nameOne, sizeof(namePathOne));

			// Check if the string ends with PEM extension:
			if ((lenOne = strlen(nameOne)) > 3 &&
			    strcmp(nameOne + lenOne - 4, ".pem") == 0) {

				counterFileOne++;

				// get values from PEM file:
				// getNandEFromFile(&nOne, &eOne, namePathOne);
				getNandEFromFile(&nOne, &eOne, namePathOne);

				// Recursivity begans:
				dTwo = opendir(mainInput->pPath);

				if (dTwo) {

					while ((dirTwo = readdir(dTwo)) !=
					       NULL) {

						// nameOne = dirTwo->d_name;

						memset(nameTwo, '\0',
						       sizeof(nameTwo));
						memcpy(nameTwo, dirTwo->d_name,
						       strlen(dirTwo->d_name));

						memset(namePathTwo, '\0',
						       sizeof(namePathTwo));

						strncat(namePathTwo,
							mainInput->pPath,
							sizeof(namePathTwo));
						strncat(namePathTwo, nameTwo,
							sizeof(namePathTwo));

						// Check that the file Two is
						// not the same as the file One:
						if (strcmp(nameOne, nameTwo) !=
						    0) {

							// Check if the string
							// ends with PEM
							// extension in second
							// File
							if ((lenTwo = strlen(
								 nameTwo)) >
								3 &&
							    strcmp(
								nameTwo +
								    lenTwo - 4,
								".pem") == 0) {

								counterFile++;

								getNandEFromFile(
								    &nTwo,
								    &eTwo,
								    namePathTwo);

								// if nTwo and
								// eTwo exists:
								if (nTwo !=
									NULL &&
								    eTwo !=
									NULL &&
								    nOne !=
									NULL &&
								    eOne !=
									NULL) {

									// 1.
									// Find
									// GCD
									// between
									// nOne
									// and
									// nTwo

									// int
									// BN_gcd(BIGNUM
									// *r,
									// BIGNUM
									// *a,
									// BIGNUM
									// *b,
									// BN_CTX
									// *ctx);
									gcdBothInt = BN_gcd(
									    gcdBN,
									    nOne,
									    nTwo,
									    CTXAux);
									// free(CTXAux);

									// 2. If
									// GCD >
									// 1
									// then
									// GCD =
									// pCommon
									unityInt = BN_dec2bn(
									    &unityBN,
									    "1");
									// comparedPQ
									// =
									// BN_cmp(numA,
									// numB);
									gcdCmpInt = BN_cmp(
									    gcdBN,
									    unityBN);

									// gcdBNStr
									// =
									// BN_bn2dec(gcdBN);
									// unityBNStr
									// =
									// BN_bn2dec(unityBN);
									// printf("gcdBN
									// = %s
									// unityBN
									// = %s
									// counterFile
									// = %d
									// nameOne
									// = %s
									// nameTwo
									// = %s
									// counterFileOne
									// = %d
									// counterAux
									// = %d
									// \n",
									// gcdBNStr,
									// unityBNStr,
									// counterFile,
									// nameOne,
									// nameTwo,
									// counterFileOne,
									// counterAux);

									if (gcdCmpInt >
									    0) {

										printf(
										    "\n\nINFO - GCD is Bigger than one, therefore RSA can be cracked\n");

										pBoth = BN_dup(
										    gcdBN);

										// 3. qOne = nOne / pCommon   from equation p*q=n
										// int BN_div(BIGNUM *dv, BIGNUM *rem, const BIGNUM *a, const BIGNUM *d,BN_CTX *ctx);
										divOneInt = BN_div(
										    qOne,
										    NULL,
										    nOne,
										    pBoth,
										    CTXAux);
										// free(CTXAux);
										// 3.2 qTwo = nTwo / pCommon
										divTwoInt = BN_div(
										    qTwo,
										    NULL,
										    nTwo,
										    pBoth,
										    CTXAux);
										// free(CTXAux);

										// 4. Algorithm Euclidean EGCD(p,q,n,e) --> d
										// obtainDOneInt = obtainD(dValueOne, pBoth, qOne, nOne, eOne);
										// int BN_sub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);

										// For one
										// Substract 1 (unity) to q
										qMinusOneInt = BN_sub(
										    qMinusOne,
										    qOne,
										    unityBN);
										qMinusTwoInt = BN_sub(
										    qMinusTwo,
										    qTwo,
										    unityBN);

										// Substract 1 (unity) to p
										pMinusBothInt = BN_sub(
										    pMinusBoth,
										    pBoth,
										    unityBN);

										// Calculate Totient One and Two
										totientOneInt = BN_mul(
										    TotientOne,
										    qMinusOne,
										    pMinusBoth,
										    CTXAux);
										// free(CTXAux);
										totientTwoInt = BN_mul(
										    TotientTwo,
										    qMinusTwo,
										    pMinusBoth,
										    CTXAux);
										// free(CTXAux);

										// Calculate the inverse mod in order to obtain d
										//(e*d)mod T = 1
										// BIGNUM *BN_mod_inverse(BIGNUM *r, BIGNUM *a, const BIGNUM *n, BN_CTX *ctx);

										dValueOne = BN_mod_inverse(
										    dValueOne,
										    eOne,
										    TotientOne,
										    CTXAux);
										dValueTwo = BN_mod_inverse(
										    dValueTwo,
										    eTwo,
										    TotientTwo,
										    CTXAux);

										if (dValueOne !=
											NULL &&
										    dValueOne !=
											NULL) {
											printf(
											    "Great! It has been cracked. \n");

											// 5. Build private key for one and two
											// https://www.openssl.org/docs/man3.0/man7/EVP_PKEY-RSA.html

											RSA *rsaOne =
											    RSA_new();
											RSA *rsaTwo =
											    RSA_new();

											RSA_set0_key(
											    rsaOne,
											    BN_dup(
												nOne),
											    BN_dup(
												eOne),
											    BN_dup(
												dValueOne));
											RSA_set0_key(
											    rsaTwo,
											    BN_dup(
												nTwo),
											    BN_dup(
												eTwo),
											    BN_dup(
												dValueTwo));

											// Set the factors for the rsa key
											ret = RSA_set0_factors(
											    rsaOne,
											    BN_dup(
												pBoth),
											    BN_dup(
												qOne));
											if (ret !=
											    1) {
												printf(
												    "Error while setting factors for rsaOne\n");
											}
											ret = RSA_set0_factors(
											    rsaTwo,
											    BN_dup(
												pBoth),
											    BN_dup(
												qTwo));
											if (ret !=
											    1) {
												printf(
												    "Error while setting factors for rsaOne\n");
											}

											// int RSA_set0_crt_params(RSA *r, BIGNUM *dmp1, BIGNUM *dmq1, BIGNUM *iqmp);
											// set CRT Parameters.. i hate it...
											// https://datatracker.ietf.org/doc/html/rfc3447
											// exponent1 is d mod (p - 1).
											//* exponent2 is d mod (q - 1).
											//* coefficient is the CRT coefficient q^(-1) mod p.
											// int RSA_set0_crt_params(RSA *r, BIGNUM *dmp1, BIGNUM *dmq1, BIGNUM *iqmp);

											// CAlculate for rsa One
											ret = BN_mod(
											    dmp1One,
											    dValueOne,
											    pMinusBoth,
											    CTXAux);
											// free(CTXAux);
											ret = BN_mod(
											    dmq1One,
											    dValueOne,
											    qMinusOne,
											    CTXAux);
											// free(CTXAux);
											ret = BN_mod_inverse(
											    iqmpOne,
											    qOne,
											    pBoth,
											    CTXAux);
											// free(CTXAux);

											ret = RSA_set0_crt_params(
											    rsaOne,
											    BN_dup(
												dmp1One),
											    BN_dup(
												dmq1One),
											    BN_dup(
												iqmpOne));
											if (ret !=
											    1) {
												printf(
												    "\n Error while setting CRT parameters to rsaOne.\n");
											}

											// Check Parameters:
											/*INFO FOR DEBUGGIN
											RSA_get0_crt_params(rsaOne, &dmp1, &dmq1, &iqmp);

											myStr  = BN_bn2dec(dmp1);
											printf("P - dmp1 = %s \n", myStr);

											myStr = BN_bn2dec(dmq1);
											printf("Q - dmq1 = %s \n", myStr);

											myStr = BN_bn2dec(iqmp);
											printf("iqmp = %s \n", myStr);
											*/

											// FOR RSA TWO
											ret = BN_mod(
											    dmp1Two,
											    dValueTwo,
											    pMinusBoth,
											    CTXAux);
											// free(CTXAux);
											ret = BN_mod(
											    dmq1Two,
											    dValueTwo,
											    qMinusTwo,
											    CTXAux);
											// free(CTXAux);
											ret = BN_mod_inverse(
											    iqmpTwo,
											    qTwo,
											    pBoth,
											    CTXAux);
											// free(CTXAux);

											ret = RSA_set0_crt_params(
											    rsaTwo,
											    BN_dup(
												dmp1Two),
											    BN_dup(
												dmq1Two),
											    BN_dup(
												iqmpTwo));
											if (ret !=
											    1) {
												printf(
												    "\n Error while setting CRT parameters to rsaTwo.\n");
											}

											// Check Parameters:
											/* INFO DEBUG
											RSA_get0_crt_params(rsaTwo, &dmp1, &dmq1, &iqmp);
											myStr  = BN_bn2dec(dmp1);
											printf("P - dmp1 = %s \n", myStr);
											myStr = BN_bn2dec(dmq1);
											printf("Q - dmq1 = %s \n", myStr);
											myStr = BN_bn2dec(iqmp);
											printf("iqmp = %s \n", myStr);
											*/

											//*****************************************************************************************
											// Select File with same name and bin extension and save into an string

											//*****************************************************************************************

											// Recursivity begans:
											dOneBin = opendir(
											    mainInput
												->pPath);

											// First for dirOneBin:
											if (dOneBin) {

												// For all the files of the directory
												while (
												    (dirOneBin = readdir(
													 dOneBin)) !=
												    NULL) {

													// Select Name from file and save in nameOneBin
													memset(
													    nameOneBin,
													    '\0',
													    sizeof(
														nameOneBin));
													memcpy(
													    nameOneBin,
													    dirOneBin
														->d_name,
													    sizeof(
														dirOneBin
														    ->d_name));

													// Check if file name is larger than 4 letters (in order to contain .bin extension)
													if (strlen(
														nameOne) >
														4 &&
													    strlen(
														nameOneBin) >
														4) {
														// Check if the file name is the same but with .bin extesion
														lenOneBin =
														    strlen(
															nameOneBin);
														// lenOne = strlen(nameOneBin)
														// Check appropiate extensions for files
														if (strcmp(
															nameOneBin +
															    lenOneBin -
															    4,
															".bin") ==
															0 &&
														    strcmp(
															nameOne +
															    lenOne -
															    4,
															".pem") ==
															0) {
															// Check equal name:
															memset(
															    nameOneBinAux,
															    '\0',
															    sizeof(
																nameOneBinAux));
															mempcpy(
															    nameOneBinAux,
															    nameOneBin,
															    strlen(
																nameOneBin) -
																4);

															memset(
															    nameOneAux,
															    '\0',
															    sizeof(
																nameOneAux));
															mempcpy(
															    nameOneAux,
															    nameOne,
															    strlen(
																nameOne) -
																4);
															// Check equal name:
															if (strcmp(
																nameOneAux,
																nameOneBinAux) ==
															    0) {
																break;
															}
														}
													}
												}
											}
											closedir(
											    dOneBin);

											// Recursivity begans:
											dTwoBin = opendir(
											    mainInput
												->pPath);

											// First for dirOneBin:
											if (dTwoBin) {

												// For all the files of the directory
												while (
												    (dirTwoBin = readdir(
													 dTwoBin)) !=
												    NULL) {

													// Select Name from file and save in nameTwoBin
													memset(
													    nameTwoBin,
													    '\0',
													    sizeof(
														nameTwoBin));
													memcpy(
													    nameTwoBin,
													    dirTwoBin
														->d_name,
													    sizeof(
														dirTwoBin
														    ->d_name));

													// Check if file name is larger than 4 letters (in order to contain .bin extension)
													if (strlen(
														nameTwo) >
														4 &&
													    strlen(
														nameTwoBin) >
														4) {
														// Check if the file name is the same but with .bin extesion
														lenTwoBin =
														    strlen(
															nameTwoBin);
														// lenTwo = strlen(nameTwoBin)
														// Check appropiate extensions for files
														if (strcmp(
															nameTwoBin +
															    lenTwoBin -
															    4,
															".bin") ==
															0 &&
														    strcmp(
															nameTwo +
															    lenTwo -
															    4,
															".pem") ==
															0) {
															// Check equal name:
															memset(
															    nameTwoBinAux,
															    '\0',
															    sizeof(
																nameTwoBinAux));
															mempcpy(
															    nameTwoBinAux,
															    nameTwoBin,
															    strlen(
																nameTwoBin) -
																4);

															memset(
															    nameTwoAux,
															    '\0',
															    sizeof(
																nameTwoAux));
															mempcpy(
															    nameTwoAux,
															    nameTwo,
															    strlen(
																nameTwo) -
																4);
															// Check equal name:
															if (strcmp(
																nameTwoAux,
																nameTwoBinAux) ==
															    0) {
																// Save Name and Path Two Bin
																break;
															}
														}
													}
												}
											}

											closedir(
											    dTwoBin);

											// 5. Build private key for one and two
											// https://www.openssl.org/docs/man3.0/man3/EVP_PKEY_CTX_new.html

											printf(
											    "nameOne (PEM File) =  %s              ||              nameOneBin (Binary File) =  %s \n",
											    nameOne,
											    nameOneBin);
											printf(
											    "nameTwo (PEM File) =  %s              ||              nameTwoBin (Binary File) =  %s \n",
											    nameTwo,
											    nameTwoBin);

											/*
											//Select Name from file and save in nameOneBin
											memset(nameOneBin, '\0', sizeof(nameOneBin));
											//strncpy(nameOneBin, dirOneBin->d_name, sizeof(nameOneBin));
											//Possible Error
											memcpy(nameOneBin, dirOneBin->d_name, sizeof(dirOneBin->d_name));
											*/

											// Create Path + Name for one
											memset(
											    namePathOneBin,
											    '\0',
											    sizeof(
												namePathOneBin));
											strncat(
											    namePathOneBin,
											    mainInput
												->pPath,
											    sizeof(
												namePathOneBin));
											strncat(
											    namePathOneBin,
											    nameOneBin,
											    sizeof(
												namePathOneBin));

											/*
											//Select Name from file and save in nameTwoBin
											memset(nameTwoBin, '\0', sizeof(nameTwoBin));
											//Possible error
											memcpy(nameTwoBin, dirTwoBin->d_name, sizeof(dirTwoBin->d_name));
											*/
											// Create Path + Name for Two #ERROR HERE
											memset(
											    namePathTwoBin,
											    '\0',
											    sizeof(
												namePathTwoBin));
											strncat(
											    namePathTwoBin,
											    mainInput
												->pPath,
											    sizeof(
												namePathTwoBin));
											strncat(
											    namePathTwoBin,
											    nameTwoBin,
											    sizeof(
												namePathTwoBin));

											// FILE BIN TWO name Creation with path
											memset(
											    realOneFileName,
											    '\0',
											    sizeof(
												realOneFileName));
											strncpy(
											    realOneFileName,
											    nameOneBin,
											    sizeof(
												realOneFileName));

											memset(
											    realOneFileNamePlusPath,
											    '\0',
											    sizeof(
												realOneFileNamePlusPath));
											strncpy(
											    realOneFileNamePlusPath,
											    namePathOneBin,
											    sizeof(
												realOneFileNamePlusPath));

											// File Buffering for file BIN two START
											fileOneBin = fopen(
											    namePathOneBin,
											    "r");
											if (fileOneBin) {
												fseek(
												    fileOneBin,
												    0,
												    SEEK_END);
												lengthOneBin =
												    ftell(
													fileOneBin);
												fseek(
												    fileOneBin,
												    0,
												    SEEK_SET);
												bufferOneBin =
												    malloc(
													lengthOneBin);
												if (bufferOneBin) {
													fread(
													    bufferOneBin,
													    1,
													    lengthOneBin,
													    fileOneBin);
												}
												fclose(
												    fileOneBin);
											} // File Buffering for file BIN two END

											// FILE BIN TWO name Creation with path
											memset(
											    realTwoFileName,
											    '\0',
											    sizeof(
												realTwoFileName));
											strncpy(
											    realTwoFileName,
											    nameTwoBin,
											    strlen(
												nameTwoBin));

											memset(
											    realTwoFileNamePlusPath,
											    '\0',
											    sizeof(
												realTwoFileNamePlusPath));
											strncpy(
											    realTwoFileNamePlusPath,
											    namePathTwoBin,
											    strlen(
												realTwoFileNamePlusPath));

											// File Buffering for file BIN two
											fileTwoBin = fopen(
											    namePathTwoBin,
											    "r");
											if (fileTwoBin) {
												fseek(
												    fileTwoBin,
												    0,
												    SEEK_END);
												lengthTwoBin =
												    ftell(
													fileTwoBin);
												fseek(
												    fileTwoBin,
												    0,
												    SEEK_SET);
												bufferTwoBin =
												    malloc(
													lengthTwoBin);
												if (bufferTwoBin) {
													fread(
													    bufferTwoBin,
													    1,
													    lengthTwoBin,
													    fileTwoBin);
												}
												fclose(
												    fileTwoBin);
											}

											// EDN File Buffering for file BIN two

											// sizeLengthTwoBin = strlen(lengthOneBin);
											// sizeLengthOneBin = strlen(lengthTwoBin);

											// sizeLengthTwoBin = sizeof(bufferTwoBin);
											// sizeLengthOneBin = sizeof(bufferOneBin);

											// FIXME BUFFER LENGTH
											toOne = malloc(
											    RSA_size(
												rsaOne));
											toTwo = malloc(
											    RSA_size(
												rsaTwo));
											// printf("RSA size rsaOne = %d",RSA_size(rsaOne));
											// printf("RSA size rsaTwo = %d",RSA_size(rsaTwo));
											// unsigned char toOne[2048];
											// unsigned char toTwo[2048];

											// RSA_private_decrypt(sizeLengthOneBin, bufferOneBin, toOne, rsaOne, RSA_PKCS1_PADDING);
											sizeOneDecrypted = RSA_private_decrypt(
											    lengthOneBin,
											    bufferOneBin,
											    toOne,
											    rsaOne,
											    RSA_PKCS1_PADDING);
											printf(
											    "Message Decrypted One = %.*s \n",
											    sizeOneDecrypted,
											    toOne);

											// printf("BufferOneBin %s \n", bufferOneBin);

											// RSA_private_decrypt(sizeLengthTwoBin, bufferTwoBin, toTwo, rsaTwo, RSA_PKCS1_PADDING);
											sizeTwoDecrypted = RSA_private_decrypt(
											    lengthTwoBin,
											    bufferTwoBin,
											    toTwo,
											    rsaTwo,
											    RSA_PKCS1_PADDING);
											printf(
											    "Message Decrypted Two = %.*s \n",
											    sizeTwoDecrypted,
											    toTwo);

											// printf("BufferTwoBin %s \n", bufferTwoBin);
											// ToDo Version 0.001
											// Here save .pem private key in file for fileOne

											// File One
											strncpy(
											    filePrivateKeyOnePath,
											    mainInput
												->outputPathAbs,
											    sizeof(
												filePrivateKeyOnePath));
											strncat(
											    filePrivateKeyOnePath,
											    basename(
												namePathOne),
											    strlen(basename(
												namePathOne)) -
												4);
											strncpy(
											    filePrivateKeyOnePathPem,
											    filePrivateKeyOnePath,
											    sizeof(
												filePrivateKeyOnePathPem));
											strncat(
											    filePrivateKeyOnePathPem,
											    "_privateKey.pem",
											    sizeof(
												filePrivateKeyOnePathPem));

											// WORKING
											BIO *bp_privateOne =
											    NULL;
											// 3. save private key

											bp_privateOne =
											    BIO_new_file(
												filePrivateKeyOnePathPem,
												"w+");
											ret = PEM_write_bio_RSAPrivateKey(
											    bp_privateOne,
											    rsaOne,
											    NULL,
											    NULL,
											    0,
											    0,
											    NULL);
											printf(
											    "Saving the RSA private key into file %s \n gives ret = %d \n",
											    filePrivateKeyOnePathPem,
											    ret);
											BIO_free(
											    bp_privateOne);

											strncpy(
											    fileMessageDecodedPathOne,
											    filePrivateKeyOnePath,
											    sizeof(
												fileMessageDecodedPathOne));
											strncat(
											    fileMessageDecodedPathOne,
											    "_message.txt",
											    sizeof(
												fileMessageDecodedPathOne));

											fileMessageOne =
											    fopen(
												fileMessageDecodedPathOne,
												"w");

											fprintf(
											    fileMessageOne,
											    "%.*s",
											    sizeOneDecrypted,
											    toOne);
											fclose(
											    fileMessageOne);

											// File Two
											strncpy(
											    filePrivateKeyTwoPath,
											    mainInput
												->outputPathAbs,
											    sizeof(
												filePrivateKeyTwoPath));
											strncat(
											    filePrivateKeyTwoPath,
											    basename(
												namePathTwo),
											    strlen(basename(
												namePathTwo)) -
												4);

											strncpy(
											    filePrivateKeyTwoPathPem,
											    filePrivateKeyTwoPath,
											    sizeof(
												filePrivateKeyTwoPathPem));
											strncat(
											    filePrivateKeyTwoPathPem,
											    "_privateKey.pem",
											    sizeof(
												filePrivateKeyTwoPathPem));

											// NEW VERSION:
											BIO *bp_privateTwo =
											    NULL;
											// 3. save private key
											bp_privateTwo =
											    BIO_new_file(
												filePrivateKeyTwoPathPem,
												"w+");
											ret = PEM_write_bio_RSAPrivateKey(
											    bp_privateTwo,
											    rsaTwo,
											    NULL,
											    NULL,
											    0,
											    NULL,
											    NULL);
											printf(
											    "Saving the RSA private key into file %s \n gives ret = %d \n",
											    filePrivateKeyTwoPathPem,
											    ret);
											BIO_free(
											    bp_privateTwo);

											strncpy(
											    fileMessageDecodedPathTwo,
											    filePrivateKeyTwoPath,
											    sizeof(
												fileMessageDecodedPathTwo));
											strncat(
											    fileMessageDecodedPathTwo,
											    "_message.txt",
											    sizeof(
												fileMessageDecodedPathTwo));

											fileMessageTwo =
											    fopen(
												fileMessageDecodedPathTwo,
												"w");

											fprintf(
											    fileMessageTwo,
											    "%.*s",
											    sizeTwoDecrypted,
											    toTwo);
											fclose(
											    fileMessageTwo);

											// Save .pem private key in file for fileTwo
											// Save decrypted message fileOne.bin .txt
											// Save decrypted message fileTwo.bin in .txt

											RSA_free(
											    rsaOne);
											RSA_free(
											    rsaTwo);

											free(
											    bufferOneBin);
											free(
											    bufferTwoBin);
											free(
											    toOne);
											free(
											    toTwo);

										} // EDN dValueOne Right

										BN_free(
										    pBoth);

									} // End
									  // if
									  // gcdInt
									  // For
									  // when
									  // the
									  // CGD
									  // is
									  // bigger
									  // than
									  // one
									  // and
									  // the
									  // rsa
									  // can
									  // be
									  // cracked

								} // END if
								  // checking n
								  // and e One
								  // and Two not
								  // NULL
								BN_free(nTwo);
								BN_free(eTwo);
							}

						} // Check if strings name are
						  // not the same end if
					}
				}

				closedir(dTwo);
				BN_free(nOne);
				BN_free(eOne);
			}
		} // End while dirOne
	}

	closedir(dOne);

	// BN_free();
	// BN_CTX_free();
	// OSSL_PARAM_BLD_free //Not used Clean For Version 0.002
	// RSA_free();

	// FROM HERE FREE EVERYTHING POSSIBLE:
	/*
	BN_free(nOne);
	BN_free(eOne);
	BN_free(nTwo);
	BN_free(eTwo);
	*/

	BN_free(gcdBN);
	BN_free(pMinusBoth);
	BN_free(unityBN);

	BN_free(qOne);
	BN_free(qTwo);
	BN_free(qMinusOne);
	BN_free(qMinusTwo);

	BN_free(TotientOne);
	BN_free(TotientTwo);

	BN_free(dValueOne);
	BN_free(dValueTwo);

	BN_free(auxBN);

	BN_free(eRSA);
	BN_free(nRSA);
	BN_free(dRSA);

	BN_free(dmp1One);
	BN_free(dmq1One);
	BN_free(iqmpOne);

	BN_free(dmp1Two);
	BN_free(dmq1Two);
	BN_free(iqmpTwo);

	BN_CTX_free(CTXAux);

	printf("End of function crack keys from. \n");
}

void CrackPrivateKeyFromPublicKeysFiles(UserInputCorsair *mainInput)
{

	const int STR_PATH_LEN = 400;
	const int STR_BN_LEN = 600;

	DIR *dOne;
	DIR *dTwo;
	DIR *dOneBin;
	DIR *dTwoBin;

	FILE *fileOne;
	FILE *fileTwo;
	FILE *fileOneBin;
	FILE *fileTwoBin;

	struct dirent *dirOne;
	struct dirent *dirTwo;
	struct dirent *dirOneBin;
	struct dirent *dirTwoBin;

	char nameOne[STR_PATH_LEN];
	char nameTwo[STR_PATH_LEN];
	char nameOneBin[STR_PATH_LEN];
	char nameTwoBin[STR_PATH_LEN];

	long lengthOneBin, lengthTwoBin;

	char *bufferOneBin, *bufferTwoBin;

	int lenOne, lenTwo, gcdBothInt, gcdCmpInt, unityInt, divOneInt,
	    divTwoInt, obtainDOneInt, obtainDTwoInt, lenOneBin, lenTwoBin;

	const BIGNUM *nOne;
	const BIGNUM *eOne;
	const BIGNUM *nTwo;
	const BIGNUM *eTwo;

	/*const BIGNUM* nOne = BN_new();
	 const BIGNUM* eOne = BN_new();
	 const BIGNUM* nTwo = BN_new();
	 const BIGNUM* eTwo = BN_new();
	       */

	char *nOneStr, *eOneStr, *nTwoStr, *eTwoStr, *TotientOneStr,
	    *qMinusOneStr, *pMinusBothStr, *qOneStr, *pBothStr, *gcdBNStr,
	    *unityBNStr;

	char namePathOne[STR_PATH_LEN];
	char namePathTwo[STR_PATH_LEN];
	char namePathOneBin[STR_PATH_LEN];
	char namePathTwoBin[STR_PATH_LEN];

	char realOneFileName[STR_PATH_LEN];
	char realOneFileNamePlusPath[STR_PATH_LEN];
	char realTwoFileName[STR_PATH_LEN];
	char realTwoFileNamePlusPath[STR_PATH_LEN];

	char nameOneAux[STR_PATH_LEN];
	char nameOneBinAux[STR_PATH_LEN];
	char nameTwoAux[STR_PATH_LEN];
	char nameTwoBinAux[STR_PATH_LEN];

	size_t sizeLengthOneBin = 0;
	size_t sizeLengthTwoBin = 0;
	size_t secretOneLength = 0;
	size_t secretTwoLength = 0;

	int sizeModulusNOne = 0;
	int sizeModulusNTwo = 0;

	unsigned char *secretBufferOneBin;
	unsigned char *secretBufferTwoBin;

	// BIGNUM* gcdBoth = BN_new();
	// PB
	BIGNUM *gcdBN = BN_new();
	// BIGNUM* gcdBN;
	// BIGNUM* pBoth = BN_new();
	BIGNUM *pBoth;

	BIGNUM *pMinusBoth = BN_new();

	BIGNUM *unityBN = BN_new();

	BIGNUM *qOne = BN_new();
	BIGNUM *qTwo = BN_new();
	BIGNUM *qMinusOne = BN_new();
	BIGNUM *qMinusTwo = BN_new();

	int qMinusOneInt, qMinusTwoInt, pMinusBothInt;
	int totientOneInt, totientTwoInt;

	int counterFile = 0;
	int counterFileOne = 0;
	int counterAux = 0;

	BIGNUM *TotientOne = BN_new();
	BIGNUM *TotientTwo = BN_new();

	// BIGNUM* dValueOne = BN_new();
	// BIGNUM* dValueTwo = BN_new();
	BIGNUM *dValueOne;
	BIGNUM *dValueTwo;

	int nOneSize, eOneSize, dOneSize, nTwoSize, eTwoSize, dTwoSize;

	int myErrorDec, errorAuxInt;

	// EVP_PKEY_CTX *ctxOne;
	EVP_PKEY_CTX *ctxTwo = NULL;
	EVP_PKEY_CTX *ctxOne = NULL;
	// EVP_PKEY_CTX *ctxOne = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
	// pkeyOne = NULL;

	// EVP_PKEY *pkeyOne = NULL;
	// EVP_PKEY *pkeyTwo = NULL;

	int validationKeyOne = NULL;
	int validationKeyTwo = NULL;

	int validationEcKeyOne = 0;
	int validationEcKeyTwo = 0;

	unsigned long errorLongAux = 0;
	char *errorBufferAux;
	size_t errorBufferAuxLen;

	ENGINE *myEng = NULL;

	char *keyOneDes;
	char *keyTwoDes;
	BIGNUM *auxBN = BN_new();
	char *auxBNStr;

	/*const BIGNUM *eRSA = BN_new();
	const BIGNUM *nRSA = BN_new();
	const BIGNUM *dRSA = BN_new();
	*/

	const BIGNUM *eRSAOne;
	const BIGNUM *nRSAOne;
	const BIGNUM *dRSAOne;
	const BIGNUM *eRSATwo;
	const BIGNUM *nRSATwo;
	const BIGNUM *dRSATwo;

	// const RSA *rsa_key = RSA_new_method(NULL);

	char *eStr, *nStr, *dStr;

	FILE *filePrivateKeyOne;
	FILE *fileMessageOne;

	char filePrivateKeyOnePath[4000];
	char filePrivateKeyOnePathPem[4000];
	char filePrivateKeyOneName[1000];
	char fileMessageDecodedPathOne[4000];

	FILE *filePrivateKeyTwo;
	FILE *fileMessageTwo;

	char filePrivateKeyTwoPath[4000];
	char filePrivateKeyTwoPathPem[4000];
	char filePrivateKeyTwoName[1000];
	char fileMessageDecodedPathTwo[4000];
	char *toOne, *toTwo;
	size_t sizeOneDecrypted, sizeTwoDecrypted;
	int ret;

	// int RSA_set0_crt_params(RSA *r, BIGNUM *dmp1, BIGNUM *dmq1, BIGNUM
	// *iqmp);
	/*
	BIGNUM *dmp1One = BN_new();
	BIGNUM *dmq1One = BN_new();
	BIGNUM *iqmpOne = BN_new();

	BIGNUM *dmp1Two = BN_new();
	BIGNUM *dmq1Two = BN_new();
	BIGNUM *iqmpTwo = BN_new();
	*/

	BIGNUM *dmp1One = BN_new();
	BIGNUM *dmq1One = BN_new();
	BIGNUM *iqmpOne;
	// BIGNUM *iqmpOne = BN_new();

	BIGNUM *dmp1Two = BN_new();
	BIGNUM *dmq1Two = BN_new();
	BIGNUM *iqmpTwo;
	// BIGNUM *iqmpTwo = BN_new();

	// BIGNUM *retBN = BN_new();

	BN_CTX *CTXAux = BN_CTX_new();

	char *myStr;
	char *strAux;

	/*MY FUNCTION FOR 4 FILES START
	 * -----------------------------------------------------------------*/

	// get values from PEM file:

	// getNandEFromFile(&nOne, &eOne, namePathOne);
	getNandEFromFile(&nOne, &eOne, mainInput->pemFileOne4fFunc);

	// nOne = getNFromFile(namePathOne);
	// eOne = getEFromFile(namePathOne);

	// nOneStr = (char*)malloc(500);
	// eOneStr = (char*)malloc(500);

	// Free below:

	nOneStr = BN_bn2dec(nOne);
	eOneStr = BN_bn2dec(eOne);
	printf("File One %s   \nN = %s  \nE = %s \n",
	       mainInput->pemFileOne4fFunc, nOneStr, eOneStr);
	free(nOneStr);
	free(eOneStr);

	getNandEFromFile(&nTwo, &eTwo, mainInput->pemFileTwo4fFunc);

	// 1. Find GCD between nOne and nTwo

	// int BN_gcd(BIGNUM *r, BIGNUM *a, BIGNUM *b, BN_CTX *ctx);
	gcdBothInt = BN_gcd(gcdBN, nOne, nTwo, CTXAux);
	// BN_CTX_free(CTXAux);

	// 2. If GCD > 1 then GCD = pCommon
	unityInt = BN_dec2bn(&unityBN, "1");
	// comparedPQ = BN_cmp(numA, numB);
	gcdCmpInt = BN_cmp(gcdBN, unityBN);

	// gcdBNStr = BN_bn2dec(gcdBN);
	// unityBNStr = BN_bn2dec(unityBN);
	// printf("gcdBN = %s     unityBN = %s    counterFile = %d nameOne = %s
	// nameTwo = %s    counterFileOne = %d    counterAux = %d \n", gcdBNStr,
	// unityBNStr, counterFile, nameOne, nameTwo, counterFileOne,
	// counterAux);

	if (gcdCmpInt > 0) {

		printf("INFO - GCD is Bigger than one, therefore RSA can be "
		       "cracked");

		pBoth = BN_dup(gcdBN);

		// 3. qOne = nOne / pCommon   from equation p*q=n
		// int BN_div(BIGNUM *dv, BIGNUM *rem, const BIGNUM *a, const
		// BIGNUM *d,BN_CTX *ctx);
		divOneInt = BN_div(qOne, NULL, nOne, pBoth, CTXAux);
		// free(CTXAux);
		// 3.2 qTwo = nTwo / pCommon
		divTwoInt = BN_div(qTwo, NULL, nTwo, pBoth, CTXAux);
		// free(CTXAux);

		// 4. Algorithm Euclidean EGCD(p,q,n,e) --> d
		// obtainDOneInt = obtainD(dValueOne, pBoth, qOne, nOne, eOne);
		// int BN_sub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);

		// For one
		// Substract 1 (unity) to q
		qMinusOneInt = BN_sub(qMinusOne, qOne, unityBN);
		qMinusTwoInt = BN_sub(qMinusTwo, qTwo, unityBN);

		// Substract 1 (unity) to p
		pMinusBothInt = BN_sub(pMinusBoth, pBoth, unityBN);

		// Calculate Totient One and Two
		totientOneInt =
		    BN_mul(TotientOne, qMinusOne, pMinusBoth, CTXAux);
		// free(CTXAux);
		totientTwoInt =
		    BN_mul(TotientTwo, qMinusTwo, pMinusBoth, CTXAux);
		// free(CTXAux);

		// Calculate the inverse mod in order to obtain d
		//(e*d)mod T = 1
		// BIGNUM *BN_mod_inverse(BIGNUM *r, BIGNUM *a, const BIGNUM *n,
		// BN_CTX *ctx);

		dValueOne = BN_mod_inverse(NULL, eOne, TotientOne, CTXAux);
		dValueTwo = BN_mod_inverse(NULL, eTwo, TotientTwo, CTXAux);

		if (dValueOne != NULL && dValueTwo != NULL) {
			printf("\n");
			printf("Great! It has been cracked. dValue %p \n",
			       dValueOne);
			printf("\n");

			// 5. Build private key for one and two
			// https://www.openssl.org/docs/man3.0/man7/EVP_PKEY-RSA.html

			printf("Name One = %s \n ",
			       mainInput->pemFileOne4fFunc);
			printf("Name One = %s \n ",
			       mainInput->pemFileTwo4fFunc);

			auxBNStr = BN_bn2dec(nOne);
			printf("bn nOne = %s \n", auxBNStr);
			free(auxBNStr);

			auxBNStr = BN_bn2dec(eOne);
			printf("bn eOne = %s \n", auxBNStr);
			free(auxBNStr);

			auxBNStr = BN_bn2dec(dValueOne);
			printf("bn dOne = %s \n", auxBNStr);
			free(auxBNStr);

			auxBNStr = BN_bn2dec(pBoth);
			printf("bn pBoth = %s \n", auxBNStr);
			free(auxBNStr);

			auxBNStr = BN_bn2dec(qOne);
			printf("bn qOne = %s \n", auxBNStr);
			free(auxBNStr);

			RSA *rsaOne = RSA_new();
			RSA *rsaTwo = RSA_new();

			RSA_set0_key(rsaOne, BN_dup(nOne), BN_dup(eOne),
				     BN_dup(dValueOne));
			RSA_set0_key(rsaTwo, BN_dup(nTwo), BN_dup(eTwo),
				     BN_dup(dValueTwo));

			eRSAOne = BN_dup(RSA_get0_e(rsaOne));
			nRSAOne = BN_dup(RSA_get0_n(rsaOne));
			dRSAOne = BN_dup(RSA_get0_d(rsaOne));

			eStr = BN_bn2dec(eRSAOne);
			nStr = BN_bn2dec(nRSAOne);
			dStr = BN_bn2dec(dRSAOne);

			printf("n RSA One = %s \n", nStr);
			printf("e RSA One = %s \n", eStr);
			printf("d RSA One = %s \n", dStr);
			free(eStr);
			free(nStr);
			free(dStr);

			eRSATwo = BN_dup(RSA_get0_e(rsaTwo));
			nRSATwo = BN_dup(RSA_get0_n(rsaTwo));
			dRSATwo = BN_dup(RSA_get0_d(rsaTwo));

			eStr = BN_bn2dec(eRSATwo);
			nStr = BN_bn2dec(nRSATwo);
			dStr = BN_bn2dec(dRSATwo);

			printf("n RSA Two = %s \n", nStr);
			printf("e RSA Two = %s \n", eStr);
			printf("d RSA Two = %s \n", dStr);
			free(eStr);
			free(nStr);
			free(dStr);

			// Set the factors for the rsa key
			ret = RSA_set0_factors(rsaOne, BN_dup(pBoth),
					       BN_dup(qOne));
			if (ret != 1) {
				printf(
				    "Error while setting factors for rsaOne\n");
			}
			ret = RSA_set0_factors(rsaTwo, BN_dup(pBoth),
					       BN_dup(qTwo));
			if (ret != 1) {
				printf(
				    "Error while setting factors for rsaOne\n");
			}

			ret = BN_mod(dmp1One, dValueOne, pMinusBoth, CTXAux);
			ret = BN_mod(dmq1One, dValueOne, qMinusOne, CTXAux);
			iqmpOne = BN_mod_inverse(NULL, qOne, pBoth, CTXAux);

			strAux = BN_bn2dec(iqmpOne);
			printf("iqmpOne = %s\n", strAux);
			OPENSSL_free(strAux);

			if (iqmpOne == NULL) {
				printf("ERROR - Not possible to calculate mod "
				       "inverse of qOne and pBoth!\n");
			}

			ret = RSA_set0_crt_params(rsaOne, BN_dup(dmp1One),
						  BN_dup(dmq1One),
						  BN_dup(iqmpOne));
			if (ret != 1) {
				printf("\n\n Error while setting CRT "
				       "parameters to rsaOne.\n\n");
			}

			ret = BN_mod(dmp1Two, dValueTwo, pMinusBoth, CTXAux);
			ret = BN_mod(dmq1Two, dValueTwo, qMinusTwo, CTXAux);
			iqmpTwo = BN_mod_inverse(NULL, qTwo, pBoth, CTXAux);

			strAux = BN_bn2dec(iqmpTwo);
			printf("iqmpTwo = %s\n", strAux);
			if (iqmpTwo == NULL) {
				printf("ERROR - Not possible to calculate mod "
				       "inverse of qOne and pBoth!\n");
			}
			OPENSSL_free(strAux);

			ret = RSA_set0_crt_params(rsaTwo, BN_dup(dmp1Two),
						  BN_dup(dmq1Two),
						  BN_dup(iqmpTwo));
			if (ret != 1) {
				printf("\n\n Error while setting CRT "
				       "parameters to rsaTwo.\n\n");
			}

			printf("Starting decryopting...");

			/*DECRYPT WORK*/
			// File Buffering for file BIN two START
			fileOneBin = fopen(mainInput->binFileOne4fFunc, "r");
			if (fileOneBin) {
				fseek(fileOneBin, 0, SEEK_END);
				lengthOneBin = ftell(fileOneBin);
				fseek(fileOneBin, 0, SEEK_SET);
				bufferOneBin = malloc(lengthOneBin);
				if (bufferOneBin) {
					fread(bufferOneBin, 1, lengthOneBin,
					      fileOneBin);
				}
				fclose(fileOneBin);
			} // File Buffering for file BIN two END

			// File Buffering for file BIN two
			fileTwoBin = fopen(mainInput->binFileTwo4fFunc, "r");
			if (fileTwoBin) {
				fseek(fileTwoBin, 0, SEEK_END);
				lengthTwoBin = ftell(fileTwoBin);
				fseek(fileTwoBin, 0, SEEK_SET);
				bufferTwoBin = malloc(lengthTwoBin);
				if (bufferTwoBin) {
					fread(bufferTwoBin, 1, lengthTwoBin,
					      fileTwoBin);
				}
				fclose(fileTwoBin);
			}

			sizeLengthTwoBin = sizeof(bufferTwoBin);
			sizeLengthOneBin = sizeof(bufferOneBin);

			toOne = malloc(RSA_size(rsaOne));
			toTwo = malloc(RSA_size(rsaTwo));

			sizeOneDecrypted = RSA_private_decrypt(
			    lengthOneBin, bufferOneBin, toOne, rsaOne,
			    RSA_PKCS1_PADDING);
			printf("\n Message Decrypted One = %.*s \n",
			       sizeOneDecrypted, toOne);

			sizeTwoDecrypted = RSA_private_decrypt(
			    lengthTwoBin, bufferTwoBin, toTwo, rsaTwo,
			    RSA_PKCS1_PADDING);
			printf("\n Message Decrypted Two = %.*s \n",
			       sizeTwoDecrypted, toTwo);

			// ToDo Version 0.001
			// Here save .pem private key in file for fileOne

			// File One
			strncpy(filePrivateKeyOnePath, mainInput->outputPathAbs,
				sizeof(filePrivateKeyOnePath));
			strncat(filePrivateKeyOnePath,
				basename(mainInput->pemFileOne4fFunc),
				strlen(basename(mainInput->pemFileOne4fFunc)) -
				    4);

			strncpy(filePrivateKeyOnePathPem, filePrivateKeyOnePath,
				sizeof(filePrivateKeyOnePathPem));
			strncat(filePrivateKeyOnePathPem, "_privateKey.pem",
				sizeof(filePrivateKeyOnePathPem));

			// 3. save private key
			// HERE!
			BIO *bp_private = NULL;
			// 3. save private key
			bp_private =
			    BIO_new_file(filePrivateKeyOnePathPem, "w+");
			ret = PEM_write_bio_RSAPrivateKey(
			    bp_private, rsaOne, NULL, NULL, 0, NULL, NULL);
			BIO_free(bp_private);

			strncpy(fileMessageDecodedPathOne,
				filePrivateKeyOnePath,
				sizeof(fileMessageDecodedPathOne));
			strncat(fileMessageDecodedPathOne, "_message.txt",
				sizeof(fileMessageDecodedPathOne));

			fileMessageOne = fopen(fileMessageDecodedPathOne, "w");

			fprintf(fileMessageOne, "%.*s", sizeOneDecrypted,
				toOne);
			fclose(fileMessageOne);

			// File Two
			strncpy(filePrivateKeyTwoPath, mainInput->outputPathAbs,
				sizeof(filePrivateKeyTwoPath));
			strncat(filePrivateKeyTwoPath,
				basename(mainInput->pemFileTwo4fFunc),
				strlen(basename(mainInput->pemFileTwo4fFunc)) -
				    4);

			strncpy(filePrivateKeyTwoPathPem, filePrivateKeyTwoPath,
				sizeof(filePrivateKeyTwoPathPem));
			strncat(filePrivateKeyTwoPathPem, "_privateKey.pem",
				sizeof(filePrivateKeyTwoPathPem));

			strncpy(fileMessageDecodedPathTwo,
				filePrivateKeyTwoPath,
				sizeof(fileMessageDecodedPathTwo));
			strncat(fileMessageDecodedPathTwo, "_message.txt",
				sizeof(fileMessageDecodedPathTwo));

			fileMessageTwo = fopen(fileMessageDecodedPathTwo, "w");

			fprintf(fileMessageTwo, "%.*s", sizeTwoDecrypted,
				toTwo);
			fclose(fileMessageTwo);

			// 3. save private key
			bp_private =
			    BIO_new_file(filePrivateKeyTwoPathPem, "w+");
			ret = PEM_write_bio_RSAPrivateKey(
			    bp_private, rsaTwo, NULL, NULL, 0, NULL, NULL);
			BIO_free(bp_private);

			// Maybe it crashes here:

			RSA_free(rsaOne);
			RSA_free(rsaTwo);

			free(bufferOneBin);
			free(bufferTwoBin);
			free(toOne);
			free(toTwo);
			BN_free(pBoth);

			// HERE
			BN_free(eRSAOne);
			BN_free(nRSAOne);
			BN_free(dRSAOne);
			BN_free(eRSATwo);
			BN_free(nRSATwo);
			BN_free(dRSATwo);

		} else {

			printf("The keys cannot be cracked");
		}
	}

	BN_free(nOne);
	BN_free(eOne);
	BN_free(nTwo);
	BN_free(eTwo);

	BN_free(gcdBN);
	BN_free(pMinusBoth);

	BN_free(unityBN);

	BN_free(qOne);
	BN_free(qTwo);
	BN_free(qMinusOne);
	BN_free(qMinusTwo);

	BN_free(TotientOne);
	BN_free(TotientTwo);

	BN_free(dValueOne);
	BN_free(dValueTwo);

	BN_free(auxBN);

	BN_free(dmp1One);
	BN_free(dmq1One);
	BN_free(iqmpOne);

	BN_free(dmp1Two);
	BN_free(dmq1Two);
	BN_free(iqmpTwo);

	BN_CTX_free(CTXAux);

	printf("End of decryption of files.\n ");
}

void PrintHelp() { printf(helpStrGlobal); }

void CreateNRSAKeys(UserInputCorsair *mainInput)
{
	/*Create N RSA keys creates N RSA keys and saves the keys into the
	 * output folder*/

	int counter = 0;
	int numberKeys = mainInput->number_gFunc;

	char auxName[700];
	char auxNamePrivateKey[700];
	char auxNamePublicKey[700];
	char auxPathPrivateKey[5000];
	char auxPathPublicKey[5000];

	int timeInt;

	/*
	BIGNUM *dmp1 =  BN_new();
	BIGNUM *dmq1 =  BN_new();
	BIGNUM *iqmp = BN_new();
	*/

	BIGNUM *dmp1;
	BIGNUM *dmq1;
	BIGNUM *iqmp;

	// BIGNUM *q_BN =  BN_new();
	// BIGNUM *p_BN =  BN_new();
	BIGNUM *q_BN;
	BIGNUM *p_BN;

	char *auxStr;

	char *dmp1_str;
	char *dmq1_str;
	char *iqmp_str;

	BIGNUM *myCRT = BN_new();
	BIGNUM *auxBN = BN_new();
	BN_CTX *auxCTX = BN_CTX_new();

	// BIGNUM *oneBN = BN_new();
	// BN_dec2bn(oneBN,"1");

	for (counter = 0; counter < numberKeys; counter++) {
		int ret = 0;
		RSA *rsaKey = NULL;
		BIGNUM *BN_e = NULL;
		BIO *bp_public = NULL, *bp_private = NULL;

		int bits = 2048; // Length of the number n (n=p*q) in bits
		unsigned long e = RSA_F4;

		// 1. generate rsa key
		BN_e = BN_new();
		ret = BN_set_word(BN_e, e);
		if (ret == 1) {

			rsaKey = RSA_new();

			// ret = RSA_generate_key_ex(rsaKey, bits, BN_dup(BN_e),
			// NULL);
			ret = RSA_generate_key_ex(rsaKey, bits, BN_e, NULL);

			if (ret == 1) {

				// Create Name Prefix
				timeInt = (int)time(NULL);
				sprintf(auxName, "%d_%d_", timeInt, counter);

				// Create path for private key
				strncpy(auxPathPrivateKey,
					mainInput->outputPath,
					sizeof(auxPathPrivateKey));
				strncat(auxPathPrivateKey, auxName,
					sizeof(auxPathPrivateKey));
				strncat(auxPathPrivateKey, "privateKey.pem",
					sizeof(auxPathPrivateKey));

				// Create path for public key
				strncpy(auxPathPublicKey, mainInput->outputPath,
					sizeof(auxPathPublicKey));
				strncat(auxPathPublicKey, auxName,
					sizeof(auxPathPublicKey));
				strncat(auxPathPublicKey, "publicKey.pem",
					sizeof(auxPathPublicKey));

				// Fixme segmentation fault maybe
				// RSA_get0_crt_params(rsaKey, BN_dup(&dmp1),
				// BN_dup(&dmq1), BN_dup(&iqmp));
				// RSA_get0_crt_params(rsaKey, BN_dup(dmp1),
				// BN_dup(dmq1), BN_dup(iqmp));
				RSA_get0_crt_params(rsaKey, &dmp1, &dmq1,
						    &iqmp);

				dmp1_str = BN_bn2dec(dmp1);
				printf("P - dmp1 = %s \n", dmp1_str);
				OPENSSL_free(dmp1_str);

				dmq1_str = BN_bn2dec(dmq1);
				printf("Q - dmq1 = %s \n", dmq1_str);
				OPENSSL_free(dmq1_str);

				iqmp_str = BN_bn2dec(iqmp);
				printf("iqmp = %s \n", iqmp_str);
				OPENSSL_free(iqmp_str);

				RSA_get0_factors(rsaKey, &p_BN, &q_BN);
				// RSA_get0_factors(rsaKey, BN_dup(&p_BN),
				// BN_dup(&q_BN)); RSA_get0_factors(rsaKey,
				// BN_dup(p_BN), BN_dup(q_BN));

				auxStr = BN_bn2dec(p_BN);
				printf("P - p_BN = %s \n", auxStr);
				OPENSSL_free(auxStr);

				auxStr = BN_bn2dec(q_BN);
				printf("Q- q_BN = %s \n", auxStr);
				OPENSSL_free(auxStr);

				// q^(-1) mod p
				// BN_sqr(auxBN, q_BN, auxCTX);
				// BN_div(auxBN, NULL, oneBN, q_BN, auxCTX);

				// BN_sqr(auxBN, q_BN, auxCTX);
				// BN_mod(myCRT, p_BN, auxBN,  auxCTX);
				////BIGNUM *BN_mod_inverse(BIGNUM *r, BIGNUM *a,
				///const BIGNUM *n, BN_CTX *ctx);
				// modInverseBN = BN_mod_inverse(modInverseBN,
				// remModTotientToEBN, multTotientBN,
				// modInverseCTXBN);

				myCRT =
				    BN_mod_inverse(myCRT, q_BN, p_BN, auxCTX);

				auxStr = BN_bn2dec(myCRT);
				printf("Q- myCRT = %s \n", auxStr);
				free(auxStr);

				// 2. save public key
				bp_public =
				    BIO_new_file(auxPathPublicKey, "w+");
				// ret = PEM_write_bio_RSAPublicKey(bp_public,
				// rsaKey); PEM_write_bio_RSA_PUBKEY(BIO *bp,
				// RSA *x);
				ret =
				    PEM_write_bio_RSA_PUBKEY(bp_public, rsaKey);
				BIO_free_all(bp_public);

				// 3. save private key
				bp_private =
				    BIO_new_file(auxPathPrivateKey, "w+");
				ret = PEM_write_bio_RSAPrivateKey(
				    bp_private, rsaKey, NULL, NULL, 0, NULL,
				    NULL);

				BIO_free_all(bp_private);
			}

			RSA_free(rsaKey);
		}

		BN_free(BN_e);
	}

	BN_free(myCRT);
	BN_free(auxBN);

	BN_CTX_free(auxCTX);

	printf("END G Create N RSA Keys!\n");
}

void DecryptBinFile(UserInputCorsair *mainInput)
{
	// https://www.openssl.org/docs/manmaster/man3/PEM_write_bio_RSAPrivateKey.html
	// int PEM_write_bio_RSAPrivateKey(BIO *bp, RSA *x, const EVP_CIPHER
	// *enc, unsigned char *kstr, int klen, pem_password_cb *cb, void *u);
	// RSA *PEM_read_RSAPrivateKey(FILE *fp, RSA **x, pem_password_cb *cb,
	// void *u);

	int ret = 0;
	RSA *rsaKeyPrivate = NULL;
	RSA *rsaAux = NULL;
	char *pemFile[4000];
	char *binFile[4000];
	FILE *privateKeyFile = NULL;

	FILE *fileOneBin;
	size_t lengthOneBin = 0;
	unsigned char *secretBufferOneBin;
	size_t sizeOneDecrypted;
	char *toOne, *bufferOneBin;

	// auxFile = fopen(mainInput->dPrivateKeyFile)
	// binFile = mainInput->dBinFile
	strncpy(pemFile, mainInput->dPrivateKeyFile, sizeof(pemFile));
	strncpy(binFile, mainInput->dBinFile, sizeof(binFile));

	privateKeyFile = fopen(pemFile, "r");

	if (privateKeyFile != NULL) {

		rsaKeyPrivate =
		    PEM_read_RSAPrivateKey(privateKeyFile, rsaAux, NULL, NULL);

		if (rsaKeyPrivate != NULL) {
			// Dencrypt

			// File Buffering for file BIN two START
			fileOneBin = fopen(binFile, "r");
			if (fileOneBin) {
				fseek(fileOneBin, 0, SEEK_END);
				lengthOneBin = ftell(fileOneBin);
				fseek(fileOneBin, 0, SEEK_SET);
				bufferOneBin = malloc(lengthOneBin);
				if (bufferOneBin) {
					fread(bufferOneBin, 1, lengthOneBin,
					      fileOneBin);
				}
				fclose(fileOneBin);
			} // File Buffering for file BIN two END

			// FIXME BUFFER LENGTH
			// unsigned char toOne[2048];
			// unsigned char toTwo[2048];
			toOne = malloc(RSA_size(rsaKeyPrivate));

			sizeOneDecrypted = RSA_private_decrypt(
			    lengthOneBin, bufferOneBin, toOne, rsaKeyPrivate,
			    RSA_PKCS1_PADDING);
			printf("Message Decrypted = %.*s \n", sizeOneDecrypted,
			       toOne);

			free(bufferOneBin);
			free(toOne);
		}

		RSA_free(rsaKeyPrivate);

		fclose(privateKeyFile);
	}
}

void EncryptASCIIFile(UserInputCorsair *mainInput)
{
	// https://www.openssl.org/docs/manmaster/man3/PEM_write_bio_RSAPrivateKey.html
	// int PEM_write_bio_RSAPrivateKey(BIO *bp, RSA *x, const EVP_CIPHER
	// *enc, unsigned char *kstr, int klen, pem_password_cb *cb, void *u);
	// RSA *PEM_read_RSAPrivateKey(FILE *fp, RSA **x, pem_password_cb *cb,
	// void *u);

	int ret = 0;
	RSA *rsaKeyPublic = NULL;
	RSA *rsaAux = NULL;
	char *pemFile[4000];
	char *txtFile[4000];
	// char *binFileName[4000];
	char binFileName[4000];
	char *binFileNameAndPath[5000];
	FILE *publicKeyFile = NULL;

	FILE *fileOneTxt;
	FILE *fileOneBin;
	size_t lengthOneTxt = 0;
	unsigned char *secretBufferOneTxt;
	size_t sizeOneEncrypted;
	char *toOne, *bufferOneTxt;

	int lengthMaxToEncrypt;

	// auxFile = fopen(mainInput->dPrivateKeyFile)
	// txtFile = mainInput->dtxtFile
	strncpy(pemFile, mainInput->eEncryptPublicKey, sizeof(pemFile));
	strncpy(txtFile, mainInput->eEncryptTextFile, sizeof(txtFile));

	publicKeyFile = fopen(pemFile, "r");

	if (publicKeyFile != NULL) {

		// rsaKeyPublic = PEM_read_RSAPrivateKey(privateKeyFile, rsaAux,
		// NULL, NULL); ToDo - Version 0.002 - Add Password to following
		// function (3rd parameter)
		rsaKeyPublic =
		    PEM_read_RSAPublicKey(publicKeyFile, rsaAux, NULL, NULL);

		if (rsaKeyPublic != NULL) {
			// Dencrypt
			// File Buffering for file BIN two START
			size_t elem;
			fileOneTxt = fopen(txtFile, "r");
			if (fileOneTxt) {
				fseek(fileOneTxt, 0, SEEK_END);
				lengthOneTxt = ftell(fileOneTxt);
				fseek(fileOneTxt, 0, SEEK_SET);
				bufferOneTxt = malloc(lengthOneTxt);
				if (bufferOneTxt) {
					elem = fread(bufferOneTxt, 1,
						     lengthOneTxt, fileOneTxt);
				}
				fclose(fileOneTxt);
			} // File Buffering for file BIN two END

			toOne = malloc(RSA_size(rsaKeyPublic));
			lengthMaxToEncrypt = RSA_size(rsaKeyPublic);

			printf("bufferOneTxt = %.*s", lengthOneTxt,
			       bufferOneTxt);
			printf("elem = %d", elem);
			sizeOneEncrypted = RSA_public_encrypt(
			    lengthOneTxt, bufferOneTxt, toOne, rsaKeyPublic,
			    RSA_PKCS1_PADDING);
			printf("Message Encrypted = %.*s \n", sizeOneEncrypted,
			       toOne);

			if (sizeOneEncrypted == -1) {
				// Error handling:
				ERR_print_errors_fp(stderr);
			} else {
				// Save in file in output path with name of
				// txtFile changing extension from .txt or las
				// .something to .bin
				changeFileExtToBin(&binFileName,
						   sizeof(binFileName),
						   basename(txtFile));

				memset(binFileNameAndPath, '\0',
				       sizeof(binFileNameAndPath));
				strncat(binFileNameAndPath,
					mainInput->outputPath,
					sizeof(binFileNameAndPath));
				strncat(binFileNameAndPath, binFileName,
					sizeof(binFileNameAndPath));

				fileOneBin = fopen(binFileNameAndPath, "wb");
				if (fileOneBin == NULL) {
					printf("ERROR - EncryptASCIIFile -  "
					       "fileOneBin is NULL!");
				} else {
					fwrite(toOne, 1, sizeOneEncrypted,
					       fileOneBin);
					fclose(fileOneBin);
				}
			}

			free(bufferOneTxt);
			free(toOne);
		}

		RSA_free(rsaKeyPublic);
		fclose(publicKeyFile);
	}
}

void changeFileExtToBin(char **outputName, size_t sizeOutputName,
			char fileNameComplete[])
{

	int ch = '.';
	char *lastDotPosPtr;
	// char *outputName[500];
	// Find the last position of a dot character
	lastDotPosPtr = strrchr(fileNameComplete, ch);

	if (lastDotPosPtr == NULL) {
		memset(outputName, '\0', sizeOutputName);
		strncat(outputName, fileNameComplete, strlen(fileNameComplete));
		strncat(outputName, ".bin", 4);

	} else {
		memset(outputName, '\0', sizeOutputName);
		if ((lastDotPosPtr - fileNameComplete) > sizeOutputName) {
			printf("ERROR - changeFileExtToBin - "
			       "sizeof(outputName) = %d \n",
			       sizeOutputName);
		} else {
			strncat(outputName, fileNameComplete,
				(lastDotPosPtr - fileNameComplete));
			strncat(outputName, ".bin", 4);
		}
	}
	return;
}

int main(int argc, char *argv[])
{
	/*corsair is a program used to crack RSA passwords and work with RSA
	keys.

	The capabilities of this program are the following:

	-h      --> Prints the Program help.

	-p (path)   --> The main function. Reads all .pem files in the -p path
	and tries to crack the private password with other .pem files in the
	folder. If the provate key is cracked it decodes the .bin file with
	equal name as the private key ".pem" file Example of files in the folder
		      1.pem
		      2.pem
		      1.bin
		      2.bin
		    If the key of "1.pem" and "2.pem" was cracked, the program
	decrypts the files 2.bin and 2.bin. It also generates a .pem file for
	each public key cracked with the respective private key. This file will
	be named after the file containing the public key, the key type, the
	program name and the version of the program used. As example if 1.pem
	and 2.pem files containing a public key where cracked, two files will be
	created containing the private key. Those files will be named for
	corsair version 0.001: 1_privateKey_Corsair_0-001.pem
		      2_privateKey_Corsair_0-001.pem
		    The function also saves the decoded message in .txt files,
	which will be named as: 1_decryptedMessage_Corsair_0-001.txt
		      2_decryptedMessage_Corsair_0-001.txt

	-f (file1.pem file2.pem file1.bin file2.bin)  --> The flag -f does the
	same as the flag -p but for 4 specific files. It does not read
	recursively a path looking for files to crack. This flag allows working
	with files which are not named for the use of the function used for -p
							  It creates the same
	files as the function used with the -p flag (if key was cracked)

	-C ("BIGNUM IN ASCII" "BIGNUM IN ASCII")       --> The flag C calculate
	the RSA keys for the two BIGNUMs give in ASCII format and generates 2
	key .pem files. One for the public key and other for the private key.
							    Remember that the
	numbers need to:
							      1. Be integers (No
	Float are allowed)
							      2. Be Primes
							      3. Not be the same
	number

	-o (outputPath)                                 --> Specifies the ouput
	path where the output files will be stored. If not output path is
	specified the relative path "./CorsairOutputV0-001/" will be used
							   [WARNING] The program
	creates the path if it does NOT exist, but does NOT check for file
	"collision". Therefore some files in the ouput folder could be deleted.

	-h        --> Show the help of the program into terminal.

	-x (N)       --> Generate N "NOT Random" public keys, private keys and
	encrypted messages in order to check the functionability of the -p path
	function. (USED FOR DEBUGGING and TESTING)

	-g (N)      --> Generate N "YES Random" public keys, private keys and
	encrypted messages in order to check the functionability of the -d path
	function.

	-d (private_key_file.pem encrypted_file.bin)   --> Tries to decrypt the
	ecrypted_file.bin using the private key contained into the
	private_key_file.pem. If succes shows the decrypted message into
	terminal. If fails shows error into terminal.



	ToDo for Version 0.001
	- Input Read Arguments Function With Parameters stored into Struct and
	check consistency of gieven parameters
	- Help Print Function [DONE]
	- Create Output Folder if needed [DONE]
	- -p Function [DONE]
	  - Clean
	  - Create .pem files and save into output with name public key files
	  - Create .txt files and save into output path with decrypted message
	  - Free all variables
	- -f Function [DONE]
	- encrypt text function using public key




	ToDo for Version 0.002
	- H (HASH)   --> Specifies the HASH to be used for all functions
	- F (file.pem) --> Cracks the public key stored into file.pem using
	brute Force
	  - Shows expected time
	- Clean Code
	- Assure all Variables are freed
	- All functions with "no deprecated" open ssl functions
	- -C function
	- -x function using the same function as -C
	-  -g function using the same function as -C
	- -d function decrypts a file bin using a private key stored in a pem
	file
	- Function that creates the private and public key using operations and
	write theory
	- Possibility of setting the hash used for the encryption/decryption
	- CLEAN AND COMMENT CODE - REALLY IMPORTANT - NOW IT IS A MESS
	- -v Verbose Mode
	- -s Silent Mode
	- Write Docu about OpenSSl functions used
	- Output Path check for '/' in position strlen(outputPath)-1

	*/
	int BNCre1, BNCre2;
	BIGNUM *numA = BN_new();
	BIGNUM *numB = BN_new();
	// struct to save user input and pass it to functions
	UserInputCorsair mainInput;
	int outputSetInputUser = 0;

	outputSetInputUser = SetInputUser(argc, argv, &mainInput);

	PrintProgramVariables(&mainInput);

	if (mainInput.wrongUserInputBool == 0 && argc > 1) {
		// Check User Input
		CheckIntegrityProgramVariables(&mainInput);

		// If no errors detected continue with the program
		if (mainInput.wrongUserInputBool == 0) {

			// Yeaaaah
			// Call the functions depending on the booleans=ints
			if (mainInput.helpBool == 1) {
				// Priint Help
				PrintHelp();
				// crackPrivateKeyFromPublicKeys(inputFolder);
			} else if (mainInput.pFuncBool == 1) {
				// Main function
				printf("Main function starting... [flag -p]\n");
				CrackPrivateKeyFromPublicKeysFinal(&mainInput);

			} else if (mainInput.fFuncBool == 1) {
				// Main function for 4 files
				printf("Main function for 4 files starting... "
				       "[flag -f]\n");
				CrackPrivateKeyFromPublicKeysFiles(&mainInput);

			} else if (mainInput.cFuncBool == 1) {
				// Create keys with 2 BIGNUMs p and q
				printf(
				    "Creator for keys starting.. [flag -c]\n");
				CreateKeyFrom2BNs(&mainInput);
				// printf("ERROR - This function will be
				// available in version 0.002 because of miss of
				// time.");

			} else if (mainInput.xFuncBool == 1) {
				// Creates N number of keys and bin files
				// encrypted with those keys
				printf("Creating N crackeable keys... [flag "
				       "-x]\n");
				printf("ERROR - This function will be "
				       "available in version 0.002 because of "
				       "miss of time.");
				CreateNCrackableRSAKeys(&mainInput);

			} else if (mainInput.gFuncBool == 1) {
				// Create N number of NO CRACKEBLA keys and bin
				// file encrypted with those keys
				printf("Creating N NO CRACKABLE keys.. [flag "
				       "-g]\n");
				// printf("ERROR - This function will be
				// available in version 0.002 because of miss of
				// time. Now it just generates key files
				// (private and public) but no encrypted file");
				CreateNRSAKeys(&mainInput);

			} else if (mainInput.dFuncBool) {
				// Decrypts the file .bin using the private key
				// contained into the pem file
				printf("Decryption function starting... [flag "
				       "-d]\n");
				printf(
				    "ERROR - This function will be available "
				    "in version 0.002 because of miss of time. "
				    "- It can contain ERRORS!\n");
				DecryptBinFile(&mainInput);

			} else if (mainInput.eFuncBool) {
				// Decrypts the file .bin using the private key
				// contained into the pem file
				printf("Encryption function starting... [flag "
				       "-e]\n");
				printf(
				    "ERROR - This function will be available "
				    "in version 0.002 because of miss of time. "
				    "- It can contain ERRORS!\n");
				EncryptASCIIFile(&mainInput);
			}
		}

	} else {
		// Priint Help
		PrintHelp();
	}

	BN_free(numA);
	BN_free(numB);

	return 0;
}
