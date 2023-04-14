all : AES SHA2 generat_data test_all 

SHA2 : SHA2.c
	gcc -o SHA2 SHA2.c

AES : main.o AES.o
	gcc -o AES AES.o main.o

main.o : main.c
	gcc -c main.c

AES.o : AES.c 
	gcc -c AES.c

generat_data:
	python generate_test_files.py

test_all:
	python test.py

.PHONY : clean
clean : 
	-rm AES SHA2 *.o *.txt