all : AES SHA2 SM4 generat_data test_all 



SHA2 : SHA2.c
	gcc -o SHA2 SHA2.c


AES : aes_main.o AES.o
	gcc -o AES AES.o aes_main.o

aes_main.o : aes_main.c
	gcc -c aes_main.c

AES.o : AES.c 
	gcc -c AES.c


SM4 : sm4_main.o SM4.o
	gcc -o SM4 SM4.o sm4_main.o
	
sm4_main.o : sm4_main.c
	gcc -c sm4_main.c

SM4.o : SM4.c
	gcc -c SM4.c 


generat_data:
	python generate_test_files.py

test_all:
	python test.py

.PHONY : clean
clean : 
	-rm AES SHA2 SM4 sha256 *.o *.txt