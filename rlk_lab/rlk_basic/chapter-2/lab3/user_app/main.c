#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "rbtree_augmented.h"

#define NODES	10000

struct test_node {
	struct rb_node rb;
	int key;

	int val;
	int augmented;
};

static struct rb_root root = RB_ROOT;
static struct test_node nodes[NODES];

static void insert(struct test_node *node, struct rb_root *root)
{
	struct rb_node **new = &(root->rb_node), *parent = NULL;

	int key = node->key;


	while(*new) {
		parent = *new;
		if (key < rb_entry(parent, struct test_node, rb)->key)
			new = &parent->rb_left;
		else
			new = &parent->rb_right;
	}

	rb_link_node(&node->rb, parent, new);
	rb_insert_color(&node->rb, root);
}

void erase(struct test_node *node, struct rb_root *root)
{
    rb_erase(&node->rb, root);
}

static int black_path_count(struct rb_node *rb) {
	int count;
	for (count = 0; rb; rb = rb_parent(rb))
		count += !rb_is_red(rb);

	return count;
}

static void check(int nr_nodes)
{
	struct rb_node *rb;
	int count = 0, blacks = 0;
	int prev_key = 0;

	for (rb = rb_first(&root); rb; rb=rb_next(rb)) {
		struct test_node *node = rb_entry(rb, struct test_node, rb);
		if (node->key < prev_key)
			printf("[WARN] node->key(%d) < prev_key(%d)\n", node->key, prev_key);
		if (rb_is_red(rb) && (!rb_parent(rb) || rb_is_red(rb_parent(rb))))
			printf("[WARN] two red nodes\n");
		if (!count)
			blacks = black_path_count(rb);
		else if ((!rb->rb_left || !rb->rb_right) && (blacks != black_path_count(rb)))
			printf("[WARN] black count wrongs\n");

		prev_key = node->key;
		count++;
	}
}

void print_rbtree(struct rb_root *tree)
{
	struct rb_node *node;

	for (node = rb_first(tree); node; node = rb_next(node))
		printf("%d ", rb_entry(node, struct test_node, rb)->key);
	printf("\n");
}

int search_rbtree(struct rb_root *tree, int num){
	struct rb_node *node;

	for (node = rb_first(tree); node; node = rb_next(node)) {
		if (num == rb_entry(node, struct test_node, rb)->key)
			return true;
	}

	return false;
}

static void safe_flush()
{
    char c;

    while((c = getchar()) != '\n' && c != EOF);
}

int main(int argc, char *argv[])
{
	int i, j;
	int num;

	srand(time(NULL));
	for (i = 0; i < NODES; i++) {
		nodes[i].key = rand()%10000 + 1;
		nodes[i].val = rand()%10000 + 1;
	}

	/* insert */
	for(j = 0; j < NODES; j++) {
		insert(nodes + j, &root);
	}

	/* check */
	check(0);

        /* print_rbtree(&root); */
	while(1) {
		num = -2;
		printf("Please input the num which you want to search in rbtree.\n");
		printf("The input num should be 0 <= input num < 10000\n");
		printf("Input -1 to exit\n");
		printf(">>> ");

		scanf("%d", &num);

		if (num == -1)
			goto exit;

		if (num < 0 || num > 10000) {
			printf("WARNNING: Invalild input number!\n");
			safe_flush();
			continue;
		}

		if (search_rbtree(&root, num))
			printf("RESULT: Found %d in the rbtree\n", num);
		else
			printf("RESULT: Not Found %d in the rbtree\n", num);

	}
exit:
	/* erase */
	for(j = 0; j < NODES; j++) {
		erase(nodes + j, &root);
	}

	return 0;
}
