a.out : myerr.o parse.o pf.c
	gcc myerr.o parse.o pf.c -lnetfilter_queue -o a.out

myerr.o : myerr.c
	gcc -c myerr.c

parse.o : parse.c
	gcc -c parse.c


clean :
	rm a.out myerr.o parse.o
