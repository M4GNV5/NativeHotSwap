all:
	gcc main.c -ldl -lmhash -lpthread -g -fPIC -shared -o hotswap.so
	gcc -Wl,-q test/test.c -o test/test
