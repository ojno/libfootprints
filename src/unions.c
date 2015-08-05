#define _GNU_SOURCE

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include <dwarfidl/parser_includes.h>
#include <liballocs.h>
#include "footprints.h"

////////////////////////////////////////////////////////////
// struct union_node
////////////////////////////////////////////////////////////

struct union_node *union_new() {
	struct union_node *result = malloc(sizeof(struct union_node));
	memset(result, 0, sizeof(struct union_node));
	return result;
}

struct union_node *union_new_with(struct expr *e, _Bool adjacent, struct union_node *next) {
	struct union_node *result = union_new();
	result->expr = e;
	result->adjacent = adjacent;
	result->next = next;
	return result;
}

struct union_node *union_union(struct union_node *first, struct union_node *second) {
	if (first == NULL && second == NULL) {
		return NULL;
	} else if (first == NULL) {
		return second;
	} else if (second == NULL) {
		return first;
	} else {
		struct union_node *end = first;
		while (end->next != NULL) {
			end = end->next;
		}
		end->next = second;
		return first;
	}
}

struct union_node *union_add(struct union_node *first, struct expr *e) {
	if (first == NULL) {
		return union_new_with(e, false, NULL);
	} else {
		return union_union(first, union_new_with(e, first->adjacent, NULL));
	}
}

void union_free_node(struct union_node **node) {
	free(*node);
	*node = NULL;
}

void union_free(struct union_node *first) {
	struct union_node *current = first;
	struct union_node *next;
	while (current != NULL) {
		next = current->next;
		union_free_node(&current);
		current = next;
	}
}

void *_get_first_addr(struct union_node *node) {
	switch (node->expr->type) {
	case EXPR_OBJECT:
		return (void*) node->expr->object.addr;
		break;
	case EXPR_EXTENT:
		return (void*) node->expr->extent.base;
		break;
	case EXPR_UNION:
		// should already be recursively sorted
		return _get_first_addr(node->expr->unioned);
		break;
	default:
		assert(false);
	}
}

struct union_node *_union_sort_merge(struct union_node *front, struct union_node *back) {
	if (front == NULL) {
		return back;
	} else if (back == NULL) {
		return front;
	} else {
		void *front_addr = _get_first_addr(front);
		void *back_addr = _get_first_addr(back);
		if (front_addr <= back_addr) {
			front->next = _union_sort_merge(front->next, back);
			return front;
		} else {
			back->next = _union_sort_merge(front, back->next);
			return back;
		}
	}
}


void union_halves(struct union_node *head, struct union_node **front, struct union_node **back) {
	if (head == NULL || head->next == NULL) {
		*front = head;
		*back = NULL;
	} else {
		struct union_node *slow = head;
		struct union_node *fast = head->next;

		while (fast != NULL) {
			fast = fast->next;
			if (fast != NULL) {
				fast = fast->next;
				slow = slow->next;
			}
		}

		*front = head;
		*back = slow->next;
		slow->next = NULL;
	}
}

struct union_node *union_flatten(struct union_node *first) {
	if (first == NULL) {
		return NULL;
	}
	struct union_node *tail = NULL;
	struct union_node *current = first;
	struct union_node *next = NULL;
	_Bool adjacent = first->adjacent;
	while (current != NULL) {
		next = current->next;
		if (current->expr->type == EXPR_UNION) {
			if (!adjacent && current->expr->unioned->adjacent) {
				tail = union_new_with(construct_union(union_flatten(current->expr->unioned)), false, tail);
			} else {
				tail = union_union(union_flatten(current->expr->unioned), tail);
			}
		} else {
			current->next = tail;
			tail = current;
		}
		current = next;
	}

	return tail;
}

void union_sort(struct union_node **head) {
	if (head == NULL || *head == NULL) {
		return;
	}
	if ((*head)->expr->type == EXPR_UNION) {
		union_sort(&(*head)->expr->unioned);
	}
	if ((*head)->next == NULL) {
		return;
	}

	struct union_node *front, *back;
	union_halves(*head, &front, &back);
	union_sort(&front);
	union_sort(&back);
	*head = _union_sort_merge(front, back);
}

struct union_node *union_objects_to_extents(struct union_node *head) {
	if (head == NULL) {
		return NULL;
	}
	struct union_node *current = head;
	unsigned long base, length;
	while (current != NULL) {
		if (current->expr->type == EXPR_OBJECT) {
			assert(UNIQTYPE_HAS_KNOWN_LENGTH(current->expr->object.type));
			base = (unsigned long) current->expr->object.addr;
			length = current->expr->object.type->pos_maxoff;
			current->expr->type = EXPR_EXTENT;
			current->expr->extent.base = base;
			current->expr->extent.length = length;
		} else if (current->expr->type == EXPR_UNION) {
			current->expr->unioned = union_objects_to_extents(current->expr->unioned);
		}
		current = current->next;
	}
	return head;
}

size_t union_size(struct union_node *head) {
	struct union_node *current = head;
	size_t size = 0;
	while (current != NULL) {
		size++;
		current = current->next;
	}

	return size;
}

struct union_node *sorted_union_merge_extents(struct union_node *head) {
	struct union_node *current = head;
	struct union_node *extents = NULL;
	struct union_node *next = NULL;
	unsigned long base, length;
	while (current != NULL) {
		switch (current->expr->type) {
		case EXPR_EXTENT: {
			assert(current->expr->type == EXPR_EXTENT);
			base = current->expr->extent.base;
			length = current->expr->extent.length;
			next = current->next;
			while (next != NULL && next->expr->type == EXPR_EXTENT && next->expr->extent.base <= base + length) {
				length = (next->expr->extent.base + next->expr->extent.length) - base;
				next = next->next;
			}
			
			extents = union_new_with(construct_extent(base, length), false, extents);
		} break;
		case EXPR_UNION: {
			extents = union_new_with(construct_union(sorted_union_merge_extents(current->expr->unioned)),
			                         current->adjacent, extents);
			next = current->next;
		} break;
		case EXPR_VOID:
			// skip
			next = current->next;
			break;
		default:
			assert(false);
		}
		
		current = next;
	}

	return extents;
}


struct expr *eval_union(struct evaluator_state *state, struct expr *e, struct env_node *env) {
	assert(e->type == EXPR_UNION);
	struct union_node *current = e->unioned;
	struct union_node *tail = NULL;
	while (current != NULL) {
		tail = union_new_with(eval_footprint_expr(state, current->expr, env), current->adjacent, tail);
		current = current->next;
	}
	return construct_union(tail);
}

struct union_node *_union_remove_type(struct union_node *head, enum expr_types type) {
	if (head == NULL) {
		return NULL;
	} else {

		struct union_node *current = head;
		struct union_node *tail = NULL;
		while (current != NULL) {
			if (current->expr->type == EXPR_UNION) {
				tail = union_new_with(construct_union(_union_remove_type(current->expr->unioned, type)), current->adjacent, tail);
			} else if (current->expr->type != type) {
				tail = union_new_with(current->expr, current->adjacent, tail);
			}

			current = current->next;
		}

		return tail;
	}
}

