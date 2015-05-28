#include <stdio.h>

int global = 0;

void (*fptr)(void);
int play_ground(int x)
{
	return x*2+3-1;
}

int test_add(int x){
	if (x > 1)
		printf("play_ground : %d\n",play_ground(x));
		return x+test_add(x-1);
	return 1;
}



void dangerous(void) {
    printf("... this is a dangerous function ...\n");
    global = 32;
	printf("add sum %d\n",test_add(100));
}

int main(int argc, char *argv[]) {
	char ch;
    printf("Main enter\n");

    void (*foo)(void);
    foo  = &dangerous;
    fptr = &dangerous;

    foo();
    foo();
    global += 10;
    printf("global: %d\n", global);
	printf("Give something to exit\n");
	scanf("%c\n",&ch);
    printf("Main exit\n");
}
