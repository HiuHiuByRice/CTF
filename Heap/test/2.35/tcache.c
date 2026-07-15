#include <stdio.h>
#include <stdlib.h>

int main()
{
	int *ptr[1000];
	int count = 0;
	for(int j = 0; j <= 7; j++)
	{
		ptr[count] = malloc(0x40);
		count ++;
	}
	count ++;
	ptr[count] = malloc(0x50);
	printf("%d",count);

	for(int i = 0; i <= count; i++)
	{
		free(ptr[i]);
	}
	ptr[count+1] = malloc(0x40);
	return 0;
}