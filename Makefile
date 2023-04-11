AES : main.o AES.o
	gcc -o AES AES.o main.o

main.o : main.c
	gcc -c main.c

AES.o : AES.c 
	gcc -c AES.c

.PHONY : clean
clean : 
	-rm AES main.o AES.o