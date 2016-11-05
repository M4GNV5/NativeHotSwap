all:
	gcc main.c -ldl -lmhash -lpthread -g -fPIC -shared -o hotswap.so
	gcc -g -c test/test.c -o test/test.o
	gcc test/test.o -o test/test
