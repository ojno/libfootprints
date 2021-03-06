#define _GNU_SOURCE

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include <dwarfidl/parser_includes.h>
#include <liballocs.h>
#include "footprints.h"

#include "footprints_antlr_macros.h"

char *print_footprint_extents(struct footprint_node *fp, struct union_node *extents) {
	size_t n_nodes = 0;
	struct union_node *current = extents;
	while (current != NULL) {
		n_nodes++;
		current = current->next;
	}

	char *union_str[n_nodes];
	size_t total_strlen = n_nodes; // n-1 newlines and \0

	const char *direction = footprint_direction_str[fp->direction];

	current = extents;
	size_t i = 0;
	while (current != NULL) {
		assert(current->expr->type == EXPR_EXTENT);
		assert(asprintf(&(union_str[i]), "Allowed footprint: %s n=0x%lx base=0x%lx", direction, current->expr->extent.length, current->expr->extent.base) >= 0);
		assert(union_str[i]);
		total_strlen += strlen(union_str[i]);
		i++;
		current = current->next;
	}

	char *union_body = malloc(total_strlen);
	char *cur_char = union_body;

	for (i = 0; i < n_nodes; i++) {
		if (i > 0) {
			cur_char = stpcpy(cur_char, "\n");
		}
		cur_char = stpcpy(cur_char, union_str[i]);
	}

	return union_body;
}


/*void print_tree_types(void *ptr) {
	ANTLR3_BASE_TREE *ast = (ANTLR3_BASE_TREE*)ptr;
	fpdebug(state, "(%d[%s] ", GET_TYPE(ast), CCP(GET_TEXT(ast)));
	_Bool first = true;
	FOR_ALL_CHILDREN(ast) {
		if (first) {
			first = false;
		} else {
			fpdebug(state, " ");
		}
		print_tree_types(n);
	}
	fpdebug(state, ")");
	}*/

static inline char *dir(struct expr *e) {
	switch (e->direction) {
	case FP_DIRECTION_UNKNOWN:
		return "?";
	case FP_DIRECTION_READ:
		return "r";
	case FP_DIRECTION_WRITE:
		return "w";
	case FP_DIRECTION_READWRITE:
		return "rw";
	default:
		assert(false);
	}
}

char *print_expr_tree(struct expr *e) {
	if (e == NULL) return "(null)";
	char *body = NULL;
	switch (e->type) {
	case EXPR_VOID: {
		assert(asprintf(&body, "(%s void)", dir(e)) >= 0);
	} break;
	case EXPR_BINARY: {
		assert(asprintf(&body, "(%s %s %s %s)", dir(e), print_expr_tree(e->binary_op.left), binary_ops_str[e->binary_op.op], print_expr_tree(e->binary_op.right)) >= 0);
	} break;
	case EXPR_UNARY: {
		assert(asprintf(&body, "(%s %s %s)", dir(e), unary_ops_str[e->unary_op.op], print_expr_tree(e->unary_op.arg)) >= 0);
	} break;
	case EXPR_FOR: {
		assert(asprintf(&body, "(%s %s for %s in %s)", dir(e), print_expr_tree(e->for_loop.body), e->for_loop.ident, print_expr_tree(e->for_loop.over)) >= 0);
	} break;
	case EXPR_IF: {
		assert(asprintf(&body, "(%s if %s then %s else %s)", dir(e), print_expr_tree(e->if_cond.cond), print_expr_tree(e->if_cond.then), print_expr_tree(e->if_cond.otherwise)) >= 0);
	} break;
	case EXPR_SUBSCRIPT: {
		char *open_bracket;
		char *close_bracket;
		switch (e->subscript.method) {
		case SUBSCRIPT_DIRECT_BYTES:
			open_bracket = "{";
			close_bracket = "}";
			break;
		case SUBSCRIPT_DEREF_BYTES:
			open_bracket = "[{";
			close_bracket = "}]";
			break;
		case SUBSCRIPT_DEREF_SIZES:
			open_bracket = "[";
			close_bracket = "]";
			break;
		default:
			assert(false);
		}
		if (e->subscript.to) {
			assert(asprintf(&body, "(%s subscript %s %s%s .. %s%s)", dir(e), print_expr_tree(e->subscript.target), open_bracket, print_expr_tree(e->subscript.from), print_expr_tree(e->subscript.to), close_bracket) >= 0);
		} else {
			assert(asprintf(&body, "(%s subscript %s %s%s%s)", dir(e), print_expr_tree(e->subscript.target), open_bracket, print_expr_tree(e->subscript.from), close_bracket) >= 0);
		}
	} break;
	case EXPR_EXTENT: {
		assert(asprintf(&body, "(%s extent base = %lx, length = %lx)", dir(e), e->extent.base, e->extent.length) >= 0);
	} break;
	case EXPR_FUNCTION_ARGS:
	case EXPR_UNION: {
		size_t n_nodes = 0;
		struct union_node *current = e->unioned;
		while (current != NULL) {
			n_nodes++;
			current = current->next;
		}

		char *union_str[n_nodes];

		size_t total_strlen = n_nodes; // n-1 spaces and \0

		current = e->unioned;
		size_t i = 0;
		while (current != NULL) {
			union_str[i] = print_expr_tree(current->expr);
			total_strlen += strlen(union_str[i]);
			i++;
			current = current->next;
		}

		char *union_body = malloc(total_strlen);
		char *cur_char = union_body;

		for (i = 0; i < n_nodes; i++) {
			if (i > 0) {
				cur_char = stpcpy(cur_char, " ");
			}
			cur_char = stpcpy(cur_char, union_str[i]);
		}

		char *format_str;
		if (e->type == EXPR_FUNCTION_ARGS) {
			format_str = "(%s args %s)";
		} else if (e->unioned->adjacent) {
			format_str = "(%s adjacent %s)";
		} else {
			format_str = "(%s union %s)";
		}

		assert(asprintf(&body, format_str, dir(e), union_body) >= 0);
	} break;
	case EXPR_OBJECT: {
		assert(asprintf(&body, "(%s object @%p of type %s)", dir(e), e->object.addr, e->object.type->name) >= 0);
	} break;
	case EXPR_IDENT: {
		assert(asprintf(&body, "(%s ident %s)", dir(e), e->ident) >= 0);
	} break;
	case EXPR_VALUE: {
		assert(asprintf(&body, "(%s value %ld)", dir(e), e->value) >= 0);
	} break;
	case EXPR_FUNCTION: {
		size_t n_args = 0;
		struct string_node *current = e->func.args;
		while (current != NULL) {
			n_args++;
			current = current->next;
		}

		char *arg_str[n_args];
		size_t total_strlen = 2 * n_args - 1; // n-1 * ", " + \0
		current = e->func.args;
		size_t i = 0;
		while (current != NULL) {
			arg_str[i] = current->value;
			total_strlen += strlen(arg_str[i]);
			i++;
			current = current->next;
		}

		char *arg_body = malloc(total_strlen);
		char *cur_char = arg_body;

		for (i = 0; i < n_args; i++) {
			if (i > 0) {
				cur_char = stpcpy(cur_char, ", ");
			}
			cur_char = stpcpy(cur_char, arg_str[i]);
		}

		assert(asprintf(&body, "(%s function %s with args (%s) and expr (%s))", dir(e), e->func.name, arg_body, print_expr_tree(e->func.expr)) >= 0);
	} break;
	default:
		assert(false);
	}
	assert(body != NULL);
	return body;
}
