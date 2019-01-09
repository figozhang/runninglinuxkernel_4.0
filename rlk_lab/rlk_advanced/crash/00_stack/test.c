#include <stdio.h>

#define MAX_SUM 10

unsigned int cal_sum(int n)
{
	unsigned int sum;
	sum = n++;

	if (n < MAX_SUM)
		sum =+ cal_sum(n);

	return sum;
}

int main()
{
	unsigned int sum;

	sum = cal_sum(0);

	printf("sum=%d\n", sum);
	
	return 0;
}
