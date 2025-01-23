# 🔓 Corsair

RSA low randomness key cracker.

## 📃 Table of contents

1. [Corsair](#corsair)  
	1. [Introducción](#introduction)  
	1. [Instrucciones Generales](#instruccionesGenerales)  
	2. [Parte Obligatoria](#parteObligatoria)  
	3. [Parte Bonus](#parteBonus)  
2. [My Corsair](#myCorsair)  
	1. [Corsair Help](#corsairHelp)
	1. [Files](#files)  
	2. [Docker Containers](#dockerContainers)  
	3. [Configuration Files](#configurationFiles)  
	4. [Build](#build) 
	5. [Leaks](#leaks)
	5. [Tests](#tests) 
	6. [Use Examples](#useExamples)
2. [Useful Commands](#usefulCommands)
	1. [GCC Commands](#gccCommands)
	1. [Valgrind Commands](#valgrindCommands)
3. [Software](#software)  
	1. [GCC - GNU Compiler Collection](#gcc) 
	1. [GDB - GNU Debugger](#gdb) 
	1. [Open SSL](#openSSL) 
	1. [Valgrind](#valgrind) 
4. [Theory](#theory)  
3. [Sources](#sources)  
7. [Notes](#notes)
7. [To Do](#toDo)


## 🔓 Corsair <a name="corsair"/>

Resumen: Bloque de criptografía

### 📜 Introducción <a name="introduction"/>

Este proyecto introduce conceptos específicos sobre la fortaleza del algoritmo RSA y
sus vulnerabilidades potenciales. Si bien el algoritmo es considerado suficientemente fuerte
para la potencia computacional de los dispositivos actuales, ciertas formas de utilizarlo
pueden llevar a graves problemas de seguridad.

### 📖 Instrucciones generales <a name="instruccionesGenerales"/>

Para este proyecto, debes usar C como lenguaje. La lista de funciones pemitidas es la
siguiente:
• Todas las funciones de **<math.h>**\
• Todas las funciones de **<string.h>**\
• La librería **openssl**\
• Todo lo puesto en cabecera del ejercicio.


### ❗ Parte Obligatoria <a name="parteObligatoria"/>

La seguridad en la criptografía asimétrica usando claves RSA se basa en la premisa de
que es muy difícil computacionalmente factorizar los dos factores primos de un número.

“Multiplicar dos números primos p y q para obtener n” es una operación sencilla y su
complejidad no aumenta drásticamente cuando los números crecen:

[1736640013 · 1230300287 = 2136588706409583731]

En cambio, la operación inversa, “dado un número n obtener sus dos factores pri-
mos”, es una operación que se vuelve computacionalmente inviable cuando los números
involucrados son lo suficientemente grandes.

Para generar la pareja de claves, el algoritmo RSA crea una clave pública y privada
usando este concepto. Simplificando la generación de las claves, los números primos elegidos aleatoriamente p y q se multiplican para crear el módulo n que se usará tanto en
la clave privada como en la pública. Este módulo n es público pero los factores primos p
y q no.

[? · ? = 2136588706409583731]

Si tenemos dos certificados generados en un sistema cuyo generador de números alea-
torios estaba configurado al mínimo y por tanto en el que la entropía era mínima. . .

Esto puede haber dado pie a repeticiones de números primos durante distintas generaciones,
se podría haber dado el caso en el que dos módulos compartan el mismo número p o q.

[n1 = p1 · q1] [n2 = p1 · q2]


#### Ejercicio 1 - coRSAir 

| |  |
| ----------- | ----------- |
| Nombre de función		| corsair 	|
| Archivos a entregar	| *.c, *.h 	|
| Funciones autorizadas 	| printf, snprintf, write, read, open, close, malloc, free |
| Descripción 			| Bloque de criptografía: cifrados vulnerables |



Con esta información, crearás una herramienta que:

• Lea la clave pública de estos certificados y obtenga el módulo y exponente. Calcular
el resto de los datos necesarios.

• Construya la clave privada a partir de dos primos y su producto, y de ahí saque la
clave simétrica cifrada con él.

• ¡Descifre el mensaje!

### ➕ Parte Bonus <a name="parteBonus"/>

La evaluación de los bonus se hará SI Y SOLO SI la parte obligatoria es PERFECTA.
De lo contrario, los bonus serán totalmente IGNORADOS.

Puedes mejorar tu proyecto con las siguientes características:

• Documentación detallada y clara de todos los fundamentos teóricos detrás del pro-
yecto

• Implementación propia de una librería o conjunto de funciones en C para operar
con enteros de gran tamaño.

• Todo lo que se te ocurra... podrás justificarlo todo durante la evaluación.





## 🔐 My Corsair <a name="myCorsair"/>

- Features:
- 

### ❓ Corsair Help  <a name="corsairHelp"/>


```bash
wrongUserInputBool = 0 
helpBool = 1 
pFuncBool = 0 
pPath =  
fFuncBool = 0 
pemFileOne4Func =  
pemFileTwo4Func =  
binFileOne4fFunc =  
binFileTwo4fFunc =  
cFuncBool = 0 
BN_One_cFunc =  
BN_Two_cFunc =  
xFuncBool = 0 
number_xFunc = 0 
gFuncBool = 0 
number_gFunc = 0 
dFUncBool = 0 
dPrivateKeyFile =   
dBinFile =  
eFuncBool = 0 
eEncryptPublicKey =   
eEncryptTextFile =  
outputPathBool = 0
OutputPath = 

DEBUG - pwd = /home/spider/Documents/Portfolio/PortfolioFiles/CyberSecurity42/Modules/PortfolioProjects/corsair 
corsair is a program used to crack RSA passwords and work with RSA keys. 

  The capabilities of this program are the following: 

  -h      --> Prints the Program help.
  
  -p (path)   --> The main function. Reads all .pem files in the -p path and tries to crack the private password with other .pem files in the folder. If the provate key is cracked it decodes the .bin file 
              with equal name as the private key '.pem' file1
              Example of files in the folder
                1.pem
                2.pem 
                1.bin
                2.bin
              If the key of '1.pem' and '2.pem' was cracked, the program decrypts the files 2.bin and 2.bin.
              It also generates a .pem file for each public key cracked with the respective private key.
              This file will be named after the file containing the public key, the key type, the program name and the version of the program used.
              As example if 1.pem and 2.pem files containing a public key where cracked, two files will be created containing the private key. 
              Those files will be named for corsair version 0.001:
                1_privateKey_Corsair_0-001.pem
                2_privateKey_Corsair_0-001.pem
              The function also saves the decoded message in .txt files, which will be named as:
                1_decryptedMessage_Corsair_0-001.txt
                2_decryptedMessage_Corsair_0-001.txt
   
  -f (file1.pem file2.pem file1.bin file2.bin)  --> The flag -f does the same as the flag -p but for 4 specific files. It does not read recursively a path looking for files to crack.
                                                    This flag allows working with files which are not named for the use of the function used for -p
                                                    It creates the same files as the function used with the -p flag (if key was cracked)


  -g (N)      --> Generate N 'YES Random' public keys, private keys and encrypted messages in order to check the functionability of the -d path function.


 - FOR VERSION 0.002 

  -C ('BIGNUM IN ASCII' 'BIGNUM IN ASCII')-C ('BIGNUM IN ASCII' 'BIGNUM IN ASCII')       --> The flag C calculate the RSA keys for the two BIGNUMs give in ASCII format and generates 2 key .pem files. One for the public key
                                                      and other for the private key.
                                                      Remember that the numbers need to:
                                                        1. Be integers (No Float are allowed)
                                                        2. Be Primes
                                                        3. Not be the same number
                                                    
  -o (outputPath)                                 --> Specifies the ouput path where the output files will be stored. If not output path is specified the relative path './CorsairOutputV0-001/' will be used
                                                     [WARNING] The program creates the path if it does NOT exist, but does NOT check for file 'collision'. Therefore some files in the ouput folder could be deleted.    
                                                    
  -h        --> Show the help of the program into terminal.

  -x (N)       --> Generate N 'NOT Random' public keys, private keys and encrypted messages in order to check the functionability of the -p path function. (USED FOR DEBUGGING and TESTING)

  -d (private_key_file.pem encrypted_file.bin)   --> Tries to decrypt the ecrypted_file.bin using the private key contained into the private_key_file.pem.
                                                      If succes shows the decrypted message into terminal.
                                                      If fails shows error into terminal.
  -e (public_key_file.pem input_text_file.txt)   --> if the length of the text of the input_text_file is lower or equal than the maximum encryption lenght,
										this function encrypts the text and save it into the file given with the -o flag. 



  ToDo for Version 0.002
  - Input Read Arguments Function With Parameters stored into Struct and check consistency of gieven parameters
  - Help Print Function
  - Create Output Folder if needed
  - -p Function
    - Clean
    - Create .pem files and save into output with name public key files
    - Create .txt files and save into output path with decrypted message
    - Free all variables
  - -f Function
    - SAME as -p but for 4 files
  - -C function
  - -x function using the same function as -C
  - .g function using the same function as -C
  - -d function 



  ToDo for Version 0.002
  - H (HASH)   --> Specifies the HASH to be used for all functions 
  - F (file.pem) --> Cracks the public key stored into file.pem 
  - Clean Code
  - Assure all Variables are freedn
  - All functions with 'no deprecated' open ssl functions

```


###  📁 Files <a name="files"/>
- The list of files used for the project is the following:

| FILE | Function |
| ----- | -------- |
| README.md  (this file) | Readme file with some information about this project.   |
| corsair.c   | Corsair program written in C   |
|  corsair | Compiled Corsair Program    |
| corsairTest.sh  |  Bash Script used to test the several Corsair functionalities   |
|  testLeaks.sh |  Bash Script used to test leaks for all the Corsair functionalities   |
|  testLeaksOld.sh | Old Bash Script used to test leaks for all the Corsair functionalities without the capability of changing de output directory |
| testX.sh |  Bash Script to test recall capability of corsair program  |
|  Sources/ | Folder with several files used in order to test the functions of the program.   |




### 👷 Build <a name="build"/>
  
The program can be build with the gcc for two main goals:
- Distribution: Use the program normally.
- Debugging: Test, debug and improve the code.

#### Compile for distribution

- Compile standard:
```bash
	gcc corsair.c -o corsair -lm -lssl -lcrypto -w
	OR
	gcc corsair.c -o ../binaries/corsair -lm -lssl -lcrypto -w
	
```


#### Compile for Debugging
- Compile Debugging:
```bash
	gcc -o corsair -std=c11 -Wall -ggdb3 corsair.c -lssl -lcrypto -w
	gcc -o corsair -std=c11 -Wall -ggdb3 corsair.c -lssl -lcrypto -w -lm
	
	#OR
	
	gcc -o ../binaries/corsair -std=c11 -Wall -ggdb3 corsair.c -lssl -lcrypto -w
	gcc -o ../binaries/corsair -std=c11 -Wall -ggdb3 corsair.c -lssl -lcrypto -w -lm
```	



### 💧 Leaks <a name="leaks"/>

1. Compile the program with -dgb flag
```bash
	gcc -o corsair -std=c11 -Wall -ggdb3 corsair.c -lssl -lcrypto -w -lm
```

2. Run the compiled program using the utily valgrind:
```bash
	dirValRes="valgrindRes20/"
	dirValResOut="./""$dirValRes"
	mkdir $dirValRes
	
	valgrind --log-file="$dirValRes"Xout01.file --leak-check=yes --tool=memcheck ./corsair -x  4 -o "$dirValResOut"valXOut01/
```

[!] - Some leak tests are in the file: ./tests/testsLeaks.sh


### 🎯  Tests <a name="tests"/>

```bash
# Test the path option:
./corsair -p ../examples/challenge_corsair/
```

* More test in the bash script "corsairTest.sh"  in the main project folder.


### 🔨 Use Examples <a name="useExamples"/>

```bash
./corsair -h
./corsair -g 1 -o ./keys/
./corsair -f ../examples/challenge_corsair/29.pem ../examples/challenge_corsair/82.pem ../examples/challenge_corsair/29.bin ../examples/challenge_corsair/82.bin -o ./outNow3/
./corsair -p ../examples/challenge_corsair/ -o ./OutputPath13/
```


## 🔧 Software <a name="software"/>

### GCC - GNU Compiler Collection  <a name="gcc"/>

[GCC Official Website](https://gcc.gnu.org/)

- Installation:

```bash
apt install gcc

```
 
### GDB <a name="gdb"/>

[GDB Official Website](https://www.sourceware.org/gdb/)

- Installation:

```bash
apt isntall gdb
```

### OpenSSL <a name="openSSL"/> 

[OpenSSL Official Website](https://www.openssl.org/)

- Installation:

```bash
apt install libssl-dev  openssl
```

- Instructions in order to install other versions:
```
1. Install open ssl 3 or superior in debian:
	nano /etc/apt/sources.list
	
	ADD
	
	deb http://deb.debian.org/debian testing bullseye main
	deb-src http://deb.debian.org/debian testing bullseye main

	deb http://deb.debian.org/debian testing bullseye-security main
	deb-src http://deb.debian.org/debian testing bullseye-security main
	
	
	run 
	apt install openssl
	openssl version
	apt install libssl-dev
	
	apt install openssl
	apt install libssl-dev
	apt install gcc gdb valgrind 
	
	apt install openssl libssl-dev gcc gdb
```





### Valgrind <a name="valgrind"/> 
 
 [Valgrind Official Website](https://valgrind.org/)
 
 - Installation:

```bash
apt install valgrind
```



	
## 👇 Useful Commands <a name="usefulCommands"/>

### GCC Commands <a name="gccCommands"/>

### GDB Commands <a name="gdbCommands"/>

- In order to debug the C program Corsair:

```bash

1. Compile program:
	gcc -o corsair -std=c11 -Wall -ggdb3 corsair.c -lssl -lcrypto -w -lm

2. Run Program using gdb
	gdb ./corsair

3. run Command + arguments:
	run -x 10 -o ./ouputX/

4. If fault occurs use "where" command to see traceback.
	where
```

### OpenSSL Commands <a name="openSSLCommands"/>


```bash
openssl rsa -check -in privateKey.pem

openssl rsa -pubin -in 1699361481_1_publicKey.pem

openssl rsa -in alice_private.pem -pubout > alice_public.pem

openssl rsautl -encrypt -inkey bob_public.pem -pubin -in top_secret.txt -out top_secret.enc

openssl rsautl -decrypt -inkey privateKey.pem -in message.bin > message.txt

cat $(openssl rsautl -decrypt -inkey privateKey.pem -in message.bin)

cat $(openssl pkeyutl -decrypt -inkey 1699361826-privateKey.pem -in 1699361826-publicKey.bin)

```



### Valgrind Commands <a name="valgrindCommands"/>

- In order to correct corsair:
	#Source: 

```bash
		valgrind --log-file=output10.file --leak-check=yes --tool=memcheck ./corsair -h
		
		valgrind --log-file=output20.file --leak-check=yes --tool=memcheck ./corsair -g 1 -o ./keys/
		
		valgrind --log-file=output30.file --leak-check=yes --tool=memcheck ./corsair -f ./Sources/challenge_corsair/29.pem ./Sources/challenge_corsair/82.pem ./Sources/challenge_corsair/29.bin ./Sources/challenge_corsair/82.bin -o ./outNow3/
		
		./corsair -f ./Sources/challenge_corsair/97.pem ./Sources/challenge_corsair/60.pem ./Sources/challenge_corsm ./97.bin ./Sources/challenge_c.bin r/60.bin -o ./outNow3/


		
		valgrind --log-file=output40.file --leak-check=yes --tool=memcheck ./corsair -p ./Sources/challenge_corsair/ -o ./OutputPath13/
		valgrind --log-file=output41.file --leak-check=yes --track-origins=yes --tool=memcheck ./corsair -p ./Sources/challenge_corsair/ -o ./OutputPath13/
		valgrind --log-file=output41.file --leak-check=full --track-origins=yes --tool=memcheck ./corsair -p ./Sources/challenge_corsair/ -o ./OutputPath13/
```

		
- ERROR MESSSAGE VALGRIND EXAMPLE
```bash 
==43284== Memcheck, a memory error detector
==43284== Copyright (C) 2002-2009, and GNU GPL'd, by Julian Seward et al.
==43284== Using Valgrind-3.5.0 and LibVEX; rerun with -h for copyright info
==43284== Command: ./a.out
==43284== Parent PID: 39695
==43284== 
==43284== Invalid write of size 4
==43284==    at 0x4004B6: f (in /tmp/a.out)
==43284==    by 0x4004C6: main (in /tmp/a.out)
==43284==  Address 0x4c1c068 is 0 bytes after a block of size 40 alloc'd
==43284==    at 0x4A05E1C: malloc (vg_replace_malloc.c:195)
==43284==    by 0x4004A9: f (in /tmp/a.out)
==43284==    by 0x4004C6: main (in /tmp/a.out)
==43284== 
==43284== 
==43284== HEAP SUMMARY:
==43284==     in use at exit: 40 bytes in 1 blocks
==43284==   total heap usage: 1 allocs, 0 frees, 40 bytes allocated
==43284== 
==43284== 40 bytes in 1 blocks are definitely lost in loss record 1 of 1
==43284==    at 0x4A05E1C: malloc (vg_replace_malloc.c:195)
==43284==    by 0x4004A9: f (in /tmp/a.out)
==43284==    by 0x4004C6: main (in /tmp/a.out)
==43284== 
==43284== LEAK SUMMARY:
==43284==    definitely lost: 40 bytes in 1 blocks
==43284==    indirectly lost: 0 bytes in 0 blocks
==43284==      possibly lost: 0 bytes in 0 blocks
==43284==    still reachable: 0 bytes in 0 blocks
==43284==         suppressed: 0 bytes in 0 blocks
==43284== 
==43284== For counts of detected and suppressed errors, rerun with: -v
==43284== ERROR SUMMARY: 2 errors from 2 contexts (suppressed: 4 from 4)
```


## 📌 Theory <a name="theory"/>
*In some future version... RSA theroy will be here...*


## 📚 Sources <a name="sources"/>

- [OpenSSL 3.0 Official Documentation](https://docs.openssl.org/3.0/man3/)
- [GCC Official Documentation](https://gcc.gnu.org/onlinedocs/)
- [GDB Official Documentation](https://www.sourceware.org/gdb/documentation/)
- [Valgrind Official Documentation](https://valgrind.org/docs/)
- [RFC 8017 - RSA Cryptography Specifications Version](https://datatracker.ietf.org/doc/html/rfc8017)

## 📑 Notes <a name="notes"/>



## 📋 To Do <a name="toDo"/>


- Backup Program and Files
- Clean Program
- Improve console output file Function (Make it beauty)
- Names Variables Program Improve



