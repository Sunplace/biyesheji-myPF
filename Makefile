pf.out : myerr.o parse.o pf.c
	gcc myerr.o parse.o pf.c -lnetfilter_queue -lpthread -o pf.out

myerr.o : myerr.c
	gcc -c myerr.c

parse.o : parse.c
	gcc -c parse.c

mylog.o : mylog.c
	gcc -c mylog.c


clean :
	rm a.out myerr.o parse.o
