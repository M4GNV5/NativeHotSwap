#include <stdio.h>

int foo()
{
	return 1337;
}

int main()
{
	printf("foo() = %d\n", foo());
	while(getchar() != '\n');
	printf("foo() = %d\n", foo());
}
