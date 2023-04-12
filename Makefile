all : AES generat_data test_aes

AES : main.o AES.o
	gcc -o AES AES.o main.o

main.o : main.c
	gcc -c main.c

AES.o : AES.c 
	gcc -c AES.c

generat_data:
	python generate_test_files.py

test_aes:
	python test.py

.PHONY : clean
clean : 
	-rm AES main.o AES.o *.txt