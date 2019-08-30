#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "list.h"

struct num {
	int i;
	struct list_head list;
};

int main(int argc, char **argv) {
	LIST_HEAD(test_list);
	int i;
	struct num *num;
	struct num *num1;

	srand((unsigned)time(NULL));

	/* Add */	
	printf("add 100 element into list\n");
	for (i = 0; i < 100; i++) {
		num = (struct num*)malloc(sizeof(struct num));
		num->i = i;
		list_add_tail(&num->list, &test_list);
	}

	i = 0;
	/* print list */
	printf("printf the list\n");
	list_for_each_entry(num, &test_list, list) {
		printf("%2d ", num->i);
		if ((i+1)%10 == 0)
			printf("\n");
		i++;
	}
	printf("\n");

	/* Delete */
	list_for_each_entry_safe(num, num1, &test_list, list) {
		list_del(&num->list);
		free(num);
	}

	if (list_empty(&test_list))
		printf("Free test_list successfully\n");

	return 0;
}
