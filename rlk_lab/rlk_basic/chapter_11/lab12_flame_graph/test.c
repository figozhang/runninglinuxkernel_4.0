#include <stdio.h> 
#include <stdlib.h> 
#include <unistd.h>
 
void foo() 
{ 
	int i,j; 
	for(i=0; i< 10; i++) {
		usleep(100);
		j+2;
	} 
} 
int main(void) 
{ 
	int i; 
	for(i = 0; i< 100000000; i++) 
		foo(); 
	return 0; 
}

