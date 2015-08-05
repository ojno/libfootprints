#define _GNU_SOURCE

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include <unistd.h>
#include <asm/fcntl.h>
#include <sys/mman.h>
#include <asm/types.h>
#include <asm/posix_types.h>
#include <sys/syscall.h>
#include <stdarg.h>

#include <link.h>
#include <elf.h>
#include <relf.h>
#include <dwarfidl/parser_includes.h>
#include <liballocs.h>
#include "footprints.h"

#include "perform_syscall.h"

#include <dlfcn.h>

#define SYSCALL_NAME_LEN 32

const char *syscall_names[] = {
	"sys_read",
	"sys_write",
	"sys_open",
	"sys_close",
	"sys_stat",
	"sys_fstat",
	"sys_lstat",
	"sys_poll",
	"sys_lseek",
	"sys_mmap",
	"sys_mprotect",
	"sys_munmap",
	"sys_brk",
	"sys_rt_sigaction",
	"sys_rt_sigprocmask",
	"sys_rt_sigreturn",
	"sys_ioctl",
	"sys_pread64",
	"sys_pwrite64",
	"sys_readv",
	"sys_writev",
	"sys_access",
	"sys_pipe",
	"sys_select",
	"sys_sched_yield",
	"sys_mremap",
	"sys_msync",
	"sys_mincore",
	"sys_madvise",
	"sys_shmget",
	"sys_shmat",
	"sys_shmctl",
	"sys_dup",
	"sys_dup2",
	"sys_pause",
	"sys_nanosleep",
	"sys_getitimer",
	"sys_alarm",
	"sys_setitimer",
	"sys_getpid",
	"sys_sendfile",
	"sys_socket",
	"sys_connect",
	"sys_accept",
	"sys_sendto",
	"sys_recvfrom",
	"sys_sendmsg",
	"sys_recvmsg",
	"sys_shutdown",
	"sys_bind",
	"sys_listen",
	"sys_getsockname",
	"sys_getpeername",
	"sys_socketpair",
	"sys_setsockopt",
	"sys_getsockopt",
	"sys_clone",
	"sys_fork",
	"sys_vfork",
	"sys_execve",
	"sys_exit",
	"sys_wait4",
	"sys_kill",
	"sys_uname",
	"sys_semget",
	"sys_semop",
	"sys_semctl",
	"sys_shmdt",
	"sys_msgget",
	"sys_msgsnd",
	"sys_msgrcv",
	"sys_msgctl",
	"sys_fcntl",
	"sys_flock",
	"sys_fsync",
	"sys_fdatasync",
	"sys_truncate",
	"sys_ftruncate",
	"sys_getdents",
	"sys_getcwd",
	"sys_chdir",
	"sys_fchdir",
	"sys_rename",
	"sys_mkdir",
	"sys_rmdir",
	"sys_creat",
	"sys_link",
	"sys_unlink",
	"sys_symlink",
	"sys_readlink",
	"sys_chmod",
	"sys_fchmod",
	"sys_chown",
	"sys_fchown",
	"sys_lchown",
	"sys_umask",
	"sys_gettimeofday",
	"sys_getrlimit",
	"sys_getrusage",
	"sys_sysinfo",
	"sys_times",
	"sys_ptrace",
	"sys_getuid",
	"sys_syslog",
	"sys_getgid",
	"sys_setuid",
	"sys_setgid",
	"sys_geteuid",
	"sys_getegid",
	"sys_setpgid",
	"sys_getppid",
	"sys_getpgrp",
	"sys_setsid",
	"sys_setreuid",
	"sys_setregid",
	"sys_getgroups",
	"sys_setgroups",
	"sys_setresuid",
	"sys_getresuid",
	"sys_setresgid",
	"sys_getresgid",
	"sys_getpgid",
	"sys_setfsuid",
	"sys_setfsgid",
	"sys_getsid",
	"sys_capget",
	"sys_capset",
	"sys_rt_sigpending",
	"sys_rt_sigtimedwait",
	"sys_rt_sigqueueinfo",
	"sys_rt_sigsuspend",
	"sys_sigaltstack",
	"sys_utime",
	"sys_mknod",
	"sys_uselib",
	"sys_personality",
	"sys_ustat",
	"sys_statfs",
	"sys_fstatfs",
	"sys_sysfs",
	"sys_getpriority",
	"sys_setpriority",
	"sys_sched_setparam",
	"sys_sched_getparam",
	"sys_sched_setscheduler",
	"sys_sched_getscheduler",
	"sys_sched_get_priority_max",
	"sys_sched_get_priority_min",
	"sys_sched_rr_get_interval",
	"sys_mlock",
	"sys_munlock",
	"sys_mlockall",
	"sys_munlockall",
	"sys_vhangup",
	"sys_modify_ldt",
	"sys_pivot_root",
	"sys__sysctl",
	"sys_prctl",
	"sys_arch_prctl",
	"sys_adjtimex",
	"sys_setrlimit",
	"sys_chroot",
	"sys_sync",
	"sys_acct",
	"sys_settimeofday",
	"sys_mount",
	"sys_umount2",
	"sys_swapon",
	"sys_swapoff",
	"sys_reboot",
	"sys_sethostname",
	"sys_setdomainname",
	"sys_iopl",
	"sys_ioperm",
	"sys_create_module",
	"sys_init_module",
	"sys_delete_module",
	"sys_get_kernel_syms",
	"sys_query_module",
	"sys_quotactl",
	"sys_nfsservctl",
	"sys_getpmsg",
	"sys_putpmsg",
	"sys_afs_syscall",
	"sys_tuxcall",
	"sys_security",
	"sys_gettid",
	"sys_readahead",
	"sys_setxattr",
	"sys_lsetxattr",
	"sys_fsetxattr",
	"sys_getxattr",
	"sys_lgetxattr",
	"sys_fgetxattr",
	"sys_listxattr",
	"sys_llistxattr",
	"sys_flistxattr",
	"sys_removexattr",
	"sys_lremovexattr",
	"sys_fremovexattr",
	"sys_tkill",
	"sys_time",
	"sys_futex",
	"sys_sched_setaffinity",
	"sys_sched_getaffinity",
	"sys_set_thread_area",
	"sys_io_setup",
	"sys_io_destroy",
	"sys_io_getevents",
	"sys_io_submit",
	"sys_io_cancel",
	"sys_get_thread_area",
	"sys_lookup_dcookie",
	"sys_epoll_create",
	"sys_epoll_ctl_old",
	"sys_epoll_wait_old",
	"sys_remap_file_pages",
	"sys_getdents64",
	"sys_set_tid_address",
	"sys_restart_syscall",
	"sys_semtimedop",
	"sys_fadvise64",
	"sys_timer_create",
	"sys_timer_settime",
	"sys_timer_gettime",
	"sys_timer_getoverrun",
	"sys_timer_delete",
	"sys_clock_settime",
	"sys_clock_gettime",
	"sys_clock_getres",
	"sys_clock_nanosleep",
	"sys_exit_group",
	"sys_epoll_wait",
	"sys_epoll_ctl",
	"sys_tgkill",
	"sys_utimes",
	"sys_vserver",
	"sys_mbind",
	"sys_set_mempolicy",
	"sys_get_mempolicy",
	"sys_mq_open",
	"sys_mq_unlink",
	"sys_mq_timedsend",
	"sys_mq_timedreceive",
	"sys_mq_notify",
	"sys_mq_getsetattr",
	"sys_kexec_load",
	"sys_waitid",
	"sys_add_key",
	"sys_request_key",
	"sys_keyctl",
	"sys_ioprio_set",
	"sys_ioprio_get",
	"sys_inotify_init",
	"sys_inotify_add_watch",
	"sys_inotify_rm_watch",
	"sys_migrate_pages",
	"sys_openat",
	"sys_mkdirat",
	"sys_mknodat",
	"sys_fchownat",
	"sys_futimesat",
	"sys_newfstatat",
	"sys_unlinkat",
	"sys_renameat",
	"sys_linkat",
	"sys_symlinkat",
	"sys_readlinkat",
	"sys_fchmodat",
	"sys_faccessat",
	"sys_pselect6",
	"sys_ppoll",
	"sys_unshare",
	"sys_set_robust_list",
	"sys_get_robust_list",
	"sys_splice",
	"sys_tee",
	"sys_sync_file_range",
	"sys_vmsplice",
	"sys_move_pages",
	"sys_utimensat",
	"sys_epoll_pwait",
	"sys_signalfd",
	"sys_timerfd_create",
	"sys_eventfd",
	"sys_fallocate",
	"sys_timerfd_settime",
	"sys_timerfd_gettime",
	"sys_accept4",
	"sys_signalfd4",
	"sys_eventfd2",
	"sys_epoll_create1",
	"sys_dup3",
	"sys_pipe2",
	"sys_inotify_init1",
	"sys_preadv",
	"sys_pwritev",
	"sys_rt_tgsigqueueinfo",
	"sys_perf_event_open",
	"sys_recvmmsg",
	"sys_fanotify_init",
	"sys_fanotify_mark",
	"sys_prlimit64",
	"sys_name_to_handle_at",
	"sys_open_by_handle_at",
	"sys_clock_adjtime",
	"sys_syncfs",
	"sys_sendmmsg",
	"sys_setns",
	"sys_getcpu",
	"sys_process_vm_readv",
	"sys_process_vm_writev",
	"sys_kcmp",
	"sys_finit_module",
	"sys_sched_setattr",
	"sys_sched_getattr",
	"sys_renameat2",
	"sys_seccomp",
	"sys_getrandom",
	"sys_memfd_create",
	"sys_kexec_file_load",
	"sys_bpf",
	"sys_execveat"
};

struct syscall_state *syscall_state_new() {
	struct syscall_state *result = malloc(sizeof(struct syscall_state));
	memset(result, 0, sizeof(struct syscall_state));
	return result;
}

struct syscall_state *syscall_state_new_with(struct syscall_env *syscall_env, struct evaluator_state *eval, struct footprint_node *footprint, size_t syscall_num, long int syscall_args[6], char *syscall_name, long int retval, _Bool finished) {
	struct syscall_state *result = syscall_state_new();
	result->syscall_env = syscall_env;
	result->eval = eval;
	result->footprint = footprint;
	result->syscall_num = syscall_num;
	for (size_t i = 0; i < 6; i++) {
		result->syscall_args[i] = syscall_args[i];
	}
	result->syscall_name = syscall_name;
	result->retval = retval;
	result->finished = finished;
	return result;
}

void syscall_state_free(struct syscall_state **state) {
	free(*state);
	*state = NULL;
}

_Bool load_syscall_footprints_from_file(const char *filename, struct syscall_env* out) {
	struct footprint_node *footprints;
	struct env_node *defined_functions;
	footprints = parse_footprints_from_file(filename, &defined_functions);
	if (footprints) {
		*out = (struct syscall_env) {
			footprints,
			defined_functions
		};
		return true;
	} else {
		return false;
	}
}

static struct uniqtype *uniqtype_for_syscall(int syscall_num)
{
	const char *syscall_name = syscall_names[syscall_num];
	/*if (!syscall_name)
	{
		debug_printf(1, "No name for syscall number %d\n", syscall_num);
		return NULL;
		}*/
	const char prefix[] = "__ifacetype_";
	char name_buf[SYSCALL_NAME_LEN + sizeof(prefix) + 1];
	strncpy(name_buf, prefix, sizeof(prefix));
	strncat(name_buf + sizeof(prefix) - 1, syscall_name, sizeof(name_buf) - sizeof (prefix) - 1);
	name_buf[sizeof(name_buf) - 1] = '\0';
	
	struct uniqtype **found_ifacetype = dlsym(RTLD_DEFAULT, name_buf);
/*	struct uniqtype **found_ifacetype = sym_to_addr(hash_lookup_local(name_buf));
	if (!found_ifacetype) found_ifacetype = sym_to_addr(symbol_lookup_linear_local(name_buf));
	assert(found_ifacetype);*/
/*	if (!found_ifacetype)
	{
		debug_printf(1, "No ifacetype for syscall %s (check kernel DWARF)\n", name_buf);
		return NULL;
		}*/
	struct uniqtype *found_uniqtype = *found_ifacetype;
	assert(found_uniqtype);
	return found_uniqtype;
}

struct extent_node *concat_extents(struct union_node *head, struct extent_node *tail) {
	struct extent_node *result = tail;
	struct union_node *current = head;
	while (current != NULL) {
		if (current->expr->type == EXPR_EXTENT) {
			result = extent_node_new_with(current->expr->extent.base,
			                              current->expr->extent.length,
			                              result);
		} else if (current->expr->type == EXPR_UNION) {
			result = concat_extents(current->expr->unioned, result);
		} else {
			assert(false);
		}
		
		current = current->next;
	}
	return result;
}

extern inline long int
__attribute__((always_inline,gnu_inline)) 
do_syscall6(long int syscall_number, long int args[static 6])
{

	
/* Our callee-save registers are
 *	 rbp, rbx, r12, r13, r14, r15
 * but all others need to be in the clobber list.
 *	 rdi, rsi, rax, rcx, rdx, r8, r9, r10, r11
 *	 xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8, xmm9, xmm10, xmm11, xmm12, xmm13, xmm14, xmm15
 *	 condition codes, memory
 */
#define SYSCALL_CLOBBER_LIST \
	"%rdi", "%rsi", "%rax", "%rcx", "%rdx", "%r8", "%r9", "%r10", "%r11", \
	"%xmm0", "%xmm1", "%xmm2", "%xmm3", "%xmm4", "%xmm5", "%xmm6", "%xmm7", "%xmm8", \
	"%xmm9", "%xmm10", "%xmm11", "%xmm12", "%xmm13", "%xmm14", "%xmm15", \
	"cc" /*, "memory" */
#define FIX_STACK_ALIGNMENT \
	"movq %%rsp, %%rax\n\
	 andq $0xf, %%rax    # now we have either 8 or 0 in rax \n\
	 subq %%rax, %%rsp   # fix the stack pointer \n\
	 movq %%rax, %%r12   # save the amount we fixed it up by in r12 \n\
	 "
#define UNFIX_STACK_ALIGNMENT \
	"addq %%r12, %%rsp\n"

	
#define PERFORM_SYSCALL	  \
	FIX_STACK_ALIGNMENT "   \n\
	  movq %[op], %%rax       \n \
	  syscall		 \n \
	 "UNFIX_STACK_ALIGNMENT " \n \
	  movq %%rax, %[ret]      \n"
	
	
	long int ret;
	__asm__ volatile ("movq %[arg0], %%rdi \n\
			   movq %[arg1], %%rsi \n\
			   movq %[arg2], %%rdx \n\
			   movq %[arg3], %%r10 \n\
			   movq %[arg4], %%r8  \n\
			   movq %[arg5], %%r9  \n"
			   PERFORM_SYSCALL
	  : [ret]  "=r" (ret)
	  : [op]   "rm" ((long int) syscall_number)
	  , [arg0] "rm" ((long int) args[0])
	  , [arg1] "rm" ((long int) args[1])
	  , [arg2] "rm" ((long int) args[2])
	  , [arg3] "rm" ((long int) args[3])
	  , [arg4] "rm" ((long int) args[4])
	  , [arg5] "rm" ((long int) args[5])
	  : "r12", SYSCALL_CLOBBER_LIST);

	return ret;
}

void *translate_pointer(struct extent_node *mapped_guest, struct extent_node *mapped_host, size_t addr, size_t min_length) {
	if (mapped_guest == NULL || mapped_host == NULL) {
		return NULL;
	}
	struct extent_node *current_guest = mapped_guest;
	struct extent_node *current_host = mapped_host;
	while (current_guest != NULL && current_host != NULL) {
		if ((size_t)addr >= current_guest->extent.base
		    && ((size_t)addr) <= (current_guest->extent.base + current_guest->extent.length)) {
			// this extent contains it
			assert(current_host->extent.length - (((size_t)addr) - current_guest->extent.base) >= min_length);
			return (void*)(current_host->extent.base + (((size_t)addr) - current_guest->extent.base));
		}
		
		current_guest = current_guest->next;
		current_host = current_host->next;
	}
	
	// not found
	return NULL;
}

void *map_extent(struct evaluator_state *state,
                 struct extent_node **mapped_guest,
                 struct extent_node **mapped_host,
                 struct expr *expr,
                 void *defined_position) {
	assert(expr->type == EXPR_EXTENT);
	struct extent extent = expr->extent;
	void *result_ptr;

	fprintf(stderr, "map_extent called with %s\n", print_expr_tree(construct_extent(extent.base, extent.length, FP_DIRECTION_UNKNOWN)));
	
	if (defined_position == NULL) {
		result_ptr = malloc(extent.length);
	} else {
		result_ptr = defined_position;
	}

	void *bytes = _find_in_cache(state, extent.base, extent.length);
	assert(bytes != NULL);
	memcpy(result_ptr, bytes, extent.length);
	return result_ptr;
}

void *map_object(struct evaluator_state *state,
                 struct extent_node **mapped_guest,
                 struct extent_node **mapped_host,
                 struct expr *expr,
                 void *defined_position) {
	assert(expr->type == EXPR_OBJECT);
	struct object obj = expr->object;
	assert(UNIQTYPE_HAS_KNOWN_LENGTH(obj.type));
	fprintf(stderr, "map_object called with %s\n", print_expr_tree(construct_object(obj, FP_DIRECTION_UNKNOWN)));
	if (UNIQTYPE_IS_POINTER_TYPE(obj.type)) {
		// we shouldn't have mapped this already
		assert(translate_pointer(*mapped_guest, *mapped_host, (size_t)obj.addr, 0) == 0);
		int64_t guest_ptr;
		assert(object_to_value(state, obj, &guest_ptr));
		void *mapped_ptr = translate_pointer(*mapped_guest, *mapped_host, guest_ptr, 0);
		if (mapped_ptr == NULL) {
			// not mapped yet
			return NULL;
		} else {
			void **result_ptr;
			if (defined_position == NULL) {
				result_ptr = malloc(sizeof(void*));
				assert(result_ptr != NULL);
				*mapped_guest = extent_node_new_with((size_t)obj.addr, sizeof(void*), *mapped_guest);
				*mapped_host = extent_node_new_with((size_t)result_ptr, sizeof(void*), *mapped_host);
			} else {
				result_ptr = (void**) defined_position;
			}

			*result_ptr = mapped_ptr;
			return result_ptr;
		}
	} else {
		void *result_ptr;
		if (UNIQTYPE_HAS_SUBOBJECTS(obj.type)) {
			if (obj.type->is_array) {
				// array
				if (defined_position == NULL) {
					result_ptr = malloc(obj.type->pos_maxoff);
					assert(result_ptr != NULL);
				} else {
					result_ptr = defined_position;
				}
				
				for (int i = 0; i < obj.type->array_len; i++) {
					int offset = i * obj.type->contained[0].ptr->pos_maxoff;
					struct expr *item = expr_new_with(expr->direction, EXPR_OBJECT);
					item->object.type = obj.type->contained[0].ptr;
					item->object.addr = obj.addr + offset;
					item->object.direct = false;
					void *mapped_ptr = map_object(state, mapped_guest, mapped_host, item, result_ptr + offset);
					if (mapped_ptr == NULL) {
						// what about an array which contains pointers into itself...?
						if (defined_position == NULL) {
							free(result_ptr);
						}
						return NULL;
					}
				}
				
				if (defined_position == NULL) {
					*mapped_guest = extent_node_new_with((size_t)obj.addr, obj.type->pos_maxoff, *mapped_guest);
					*mapped_host = extent_node_new_with((size_t)result_ptr, obj.type->pos_maxoff, *mapped_host);
				}
				
				return result_ptr;
			} else {
				// struct
				if (defined_position == NULL) {
					result_ptr = malloc(obj.type->pos_maxoff);
					assert(result_ptr != NULL);
				} else {
					result_ptr = defined_position;
				}
				
				for (int i = 0; i < obj.type->nmemb; i++) {
					int offset = obj.type->contained[i].offset;
					struct expr *member = expr_new_with(expr->direction, EXPR_OBJECT);
					member->object.type = obj.type->contained[i].ptr;
					member->object.addr = obj.addr + offset;
					member->object.direct = false;
					void *mapped_ptr = map_object(state, mapped_guest, mapped_host, member, result_ptr + offset);
					if (mapped_ptr == NULL) {
						// what about an struct which contains pointers into itself...?
						if (defined_position == NULL) {
							free(result_ptr);
						}
						return NULL;
					}
				}

				if (defined_position == NULL) {
					*mapped_guest = extent_node_new_with((size_t)obj.addr, obj.type->pos_maxoff, *mapped_guest);
					*mapped_host = extent_node_new_with((size_t)result_ptr, obj.type->pos_maxoff, *mapped_host);
				}

				return result_ptr;
			}
		} else {
			// single object
			if (defined_position == NULL) {
				result_ptr = malloc(obj.type->pos_maxoff);
				assert(result_ptr != NULL);
			} else {
				result_ptr = defined_position;
			}
			
			switch (expr->direction) {
			case FP_DIRECTION_READ:
			case FP_DIRECTION_READWRITE:
			case FP_DIRECTION_UNKNOWN: {
				void *bytes = _find_in_cache(state, (size_t)obj.addr, obj.type->pos_maxoff);
				assert(bytes != NULL);
				memcpy(result_ptr, bytes, obj.type->pos_maxoff);
			} break;
			case FP_DIRECTION_WRITE:
				memset(result_ptr, 0, obj.type->pos_maxoff);
				break;
			default:
				assert(false);
			}
			if (defined_position == NULL) {
				*mapped_guest = extent_node_new_with((size_t)obj.addr, obj.type->pos_maxoff, *mapped_guest);
				*mapped_host = extent_node_new_with((size_t)result_ptr, obj.type->pos_maxoff, *mapped_host);
			}
			return result_ptr;
		}
	}
}

size_t _find_lowest_addr(struct union_node *head) {
	assert(head != NULL);
	switch (head->expr->type) {
	case EXPR_OBJECT:
		return (size_t) head->expr->object.addr;
		break;
	case EXPR_EXTENT:
		return head->expr->extent.base;
		break;
	case EXPR_UNION:
		return _find_lowest_addr(head->expr->unioned);
		break;
	default:
		assert(false);
	}
}

size_t _find_total_length(size_t base, struct union_node *head) {
	assert(head != NULL);
	struct union_node *current = head;
	while (current->next != NULL) {
		current = current->next;
	}
	switch (current->expr->type) {
	case EXPR_OBJECT:
		return ((size_t)current->expr->object.addr) + current->expr->object.type->pos_maxoff - base;
		break;
	case EXPR_EXTENT:
		return current->expr->extent.base + current->expr->extent.length - base;
		break;
	case EXPR_UNION: {
		size_t highest_base = _find_lowest_addr(current->expr->unioned);
		return highest_base + _find_total_length(highest_base, current->expr->unioned) - base;
	} break;
	default:
		assert(false);
	}
}

_Bool do_map_pass(struct evaluator_state *state,
                  struct extent_node **mapped_guest,
                  struct extent_node **mapped_host,
                  struct union_node **read_footprint) {
	if (read_footprint == NULL || *read_footprint == NULL) {
		return false;
	}

	fprintf(stderr, "do_map_pass called with %s\n", print_expr_tree(construct_union(*read_footprint, FP_DIRECTION_UNKNOWN)));

	_Bool modified = false;
	struct union_node *prev = NULL, *current = NULL, *next = NULL;

	if ((*read_footprint)->adjacent) {
		fprintf(stderr, "do_map_pass processing adjacent union\n");
		/* We assume the read footprint is already sorted by increasing guest address */
		size_t base = _find_lowest_addr(*read_footprint);
		size_t total_length = _find_total_length(base, *read_footprint);

		// check translate_pointer to see if we've alloced this already
		// translate_pointer asserts the length is long enough if it already exists
		void *buf = translate_pointer(*mapped_guest, *mapped_host, base, total_length);
		if (buf == NULL) {
			buf = malloc(total_length);
			*mapped_guest = extent_node_new_with(base, total_length, *mapped_guest);
			*mapped_host = extent_node_new_with((size_t)buf, total_length, *mapped_host);
		}
		assert(buf != NULL);
		current = *read_footprint;
		while (current != NULL) {
			next = current->next;

			_Bool remove_current = false;
			void *target_addr;
			switch (current->expr->type) {
			case EXPR_OBJECT:
				target_addr = (void*)(((size_t)buf) + ((size_t)current->expr->object.addr) - base);
				remove_current = (map_object(state, mapped_guest, mapped_host, current->expr, target_addr) != NULL);
				modified = (modified || remove_current);
				break;
			case EXPR_EXTENT:
				target_addr = (void*)(((size_t)buf) + current->expr->extent.base - base);
				remove_current = (map_extent(state, mapped_guest, mapped_host, current->expr, target_addr) != NULL);
				modified = (modified || remove_current);
				break;
			case EXPR_UNION:
				// TODO FIXME don't really want to have to handle
				// this recursive case but might need to later
				assert(false);
			default:
				assert(false);
			}

			if (remove_current) {
				if (prev == NULL) {
					*read_footprint = next;
					current = NULL;
				} else {
					prev->next = next;
					current = prev;
				}
			}
			
			prev = current;
			current = next;
		}
	} else {
		fprintf(stderr, "do_map_pass processing normal union\n");
		current = *read_footprint;
		while (current != NULL) {
			next = current->next;
			
			_Bool remove_current = false;
			switch (current->expr->type) {
			case EXPR_UNION:
				modified = (modified || do_map_pass(state, mapped_guest, mapped_host, &current->expr->unioned));
				remove_current = (current->expr->unioned == NULL);
				break;
			case EXPR_OBJECT:
				remove_current = (map_object(state, mapped_guest, mapped_host, current->expr, NULL) != NULL);
				modified = (modified || remove_current);
				break;
			case EXPR_EXTENT:
				remove_current = (map_extent(state, mapped_guest, mapped_host, current->expr, NULL) != NULL);
				modified = (modified || remove_current);
				break;
			default:
				assert(false);
			}

			if (remove_current) {
				if (prev == NULL) {
					*read_footprint = next;
					current = NULL;
				} else {
					prev->next = next;
					current = prev;
				}
			}
			
			prev = current;
			current = next;
		}
	}

	return modified;
}

void translate_write_extents(struct union_node *result,
                             struct extent_node *mapped_guest,
                             struct extent_node *mapped_host,
                             struct data_extent_node **write_footprint) {
	struct union_node *current = result;
	while (current != NULL) {
		if (current->expr->type == EXPR_UNION) {
			translate_write_extents(current->expr->unioned, mapped_guest, mapped_host, write_footprint);
		} else {
			assert(current->expr->type == EXPR_EXTENT);
			void *ptr = translate_pointer(mapped_guest,
			                              mapped_host,
			                              current->expr->extent.base,
			                              current->expr->extent.length);
			assert(ptr != NULL);
			*write_footprint = data_extent_node_new_with(current->expr->extent.base,
			                                             current->expr->extent.length,
			                                             ptr, *write_footprint);
		}

		current = current->next;
	}
}

void perform_syscall(struct syscall_state *state) {
	
	struct uniqtype *syscall_type = uniqtype_for_syscall(state->syscall_num);
	struct evaluator_state *eval = eval_footprint_with(state->eval,
	                                                   state->footprint,
	                                                   state->syscall_env->defined_functions,
	                                                   syscall_type,
	                                                   state->syscall_args,
	                                                   false,
	                                                   FP_DIRECTION_READWRITE);
	assert(eval->finished);

	struct union_node *read_footprint = eval->result;
	union_sort(&read_footprint);

	struct extent_node *mapped_guest = NULL;
	struct extent_node *mapped_host = NULL;

	_Bool this_pass_altered = true;
	_Bool last_pass_altered = true;
	// loop until no changes made
	while (do_map_pass(eval, &mapped_guest, &mapped_host, &read_footprint));
	// check we dealt with all of it
	assert(read_footprint == NULL);

	long int rewritten_syscall_args[6] = {0};
	for (int i = 0; i < syscall_type->array_len; i++) {
		struct uniqtype *arg_type = syscall_type->contained[i+1].ptr;
		if (UNIQTYPE_IS_POINTER_TYPE(arg_type)) {
			if (state->syscall_args[i] == 0) {
				rewritten_syscall_args[i] = 0;
			} else {
				rewritten_syscall_args[i] = (long int) translate_pointer(mapped_guest, mapped_host, state->syscall_args[i], 0);
				assert(rewritten_syscall_args[i] != 0);
			}
		} else {
			rewritten_syscall_args[i] = state->syscall_args[i];
		}
	}

	fprintf(stderr, "### PERFORMING SYSCALL %d (%s)\n", state->syscall_num, syscall_names[state->syscall_num]);
	fprintf(stderr, "### original args: 0x%16lx 0x%16lx 0x%16lx 0x%16lx 0x%16lx 0x%16lx\n",
	        state->syscall_args[0], state->syscall_args[1], state->syscall_args[2],
	        state->syscall_args[3], state->syscall_args[4], state->syscall_args[5]);
	fprintf(stderr, "### rewritten args: 0x%16lx 0x%16lx 0x%16lx 0x%16lx 0x%16lx 0x%16lx\n",
	        rewritten_syscall_args[0], rewritten_syscall_args[1], rewritten_syscall_args[2],
	        rewritten_syscall_args[3], rewritten_syscall_args[4], rewritten_syscall_args[5]);
	
	state->retval = do_syscall6(state->syscall_num, rewritten_syscall_args);
	state->finished = true;
	
	fprintf(stderr, "### returned 0x%16lx\n", state->retval);

	struct evaluator_state *write_eval = eval_footprint_with(state->eval,
	                                                         state->footprint,
	                                                         state->syscall_env->defined_functions,
	                                                         syscall_type,
	                                                         state->syscall_args,
	                                                         true,
	                                                         FP_DIRECTION_WRITE);
	assert(write_eval->finished);
	state->write_extents = NULL;

	translate_write_extents(write_eval->result, mapped_guest, mapped_host, &(state->write_extents));

	fprintf(stderr, "### write extents: %s\n", print_data_extents(state->write_extents));
}

void do_eval_pass(struct syscall_state *state) {
	state->eval->need_memory_extents = NULL;
	state->eval = eval_footprint_with(state->eval,
	                                  state->footprint,
	                                  state->syscall_env->defined_functions,
	                                  uniqtype_for_syscall(state->syscall_num),
	                                  state->syscall_args,
	                                  true,
	                                  FP_DIRECTION_READ);
	if (state->eval->finished) {
		// we have the final footprint in state->eval->result
		state->need_memory_extents = concat_extents(state->eval->result, NULL);
	} else {
		// there are more dependencies to come
		state->need_memory_extents = state->eval->need_memory_extents;
	}
}


struct evaluator_state *evaluator_state_new() {
	struct evaluator_state *result = malloc(sizeof(struct evaluator_state));
	memset(result, 0, sizeof(struct evaluator_state));
	return result;
}

struct evaluator_state *evaluator_state_new_with(struct expr *expr,
                                                 struct env_node *toplevel_env,
                                                 struct extent_node *need_memory_extents,
                                                 struct data_extent_node *have_memory_extents,
                                                 struct union_node *result,
                                                 _Bool finished) {
	struct evaluator_state *retval = evaluator_state_new();
	retval->expr = expr;
	retval->toplevel_env = toplevel_env;
	retval->need_memory_extents = need_memory_extents;
	retval->have_memory_extents = have_memory_extents;
	retval->result = result;
	retval->finished = finished;
	return retval;
}

struct syscall_state *start_syscall(struct syscall_env *syscall_env, size_t syscall_num, long int syscall_args[6]) {
	assert(syscall_num >= 0 && syscall_num < sizeof(syscall_names));
	char *syscall_name = (char*)syscall_names[syscall_num];
	struct footprint_node *footprint = get_footprints_for(syscall_env->footprints, syscall_name);
	assert(footprint);
	struct evaluator_state *eval = evaluator_state_new_with(construct_union(footprint->exprs, FP_DIRECTION_UNKNOWN),
	                                                        syscall_env->defined_functions,
	                                                        NULL,
	                                                        NULL,
	                                                        NULL,
	                                                        false);
	struct syscall_state *state = syscall_state_new_with(syscall_env, eval, footprint, syscall_num, syscall_args, syscall_name, 0, false);
	do_eval_pass(state);
	if (state->eval->finished && state->need_memory_extents == NULL) {
		// this syscall has no read footprint
		perform_syscall(state);
	} else {
		// we have final reads or dependency reads to do, fall through
	}

	return state;
}

struct data_extent_node *data_extent_union(struct data_extent_node *first, struct data_extent_node *second) {
	if (first == NULL && second == NULL) {
		return NULL;
	} else if (first == NULL) {
		return second;
	} else if (second == NULL) {
		return first;
	} else {
		struct data_extent_node *end = first;
		while (end->next != NULL) {
			end = end->next;
		}
		end->next = second;
		return first;
	}
}

char *print_data_extents(struct data_extent_node *head) {
	size_t n_nodes = 0;
	struct data_extent_node *current = head;
	while (current != NULL) {
		n_nodes++;
		current = current->next;
	}

	char *node_str[n_nodes];

	size_t total_strlen = 2 + (2 * (n_nodes - 1)) + 1; // "[]" + n-1 * ", " and \0

	current = head;
	size_t i = 0;
	while (current != NULL) {
		assert(asprintf(&(node_str[i]), "(data_extent base=0x%lx, length=0x%lx, data=%p)",
		                current->extent.base, current->extent.length, current->extent.data));
		total_strlen += strlen(node_str[i]);
		i++;
		current = current->next;
	}

	char *total_str = malloc(total_strlen);
	char *cur_char = total_str;

	cur_char = stpcpy(cur_char, "[");

	for (i = 0; i < n_nodes; i++) {
		if (i > 0) {
			cur_char = stpcpy(cur_char, " ");
		}
		cur_char = stpcpy(cur_char, node_str[i]);
	}

	cur_char = stpcpy(cur_char, "]");

	return total_str;
}


struct syscall_state *continue_syscall(struct syscall_state *state, struct data_extent_node *new_data) {
	if (new_data == NULL) {
		// no change
		return state;
	} else {
		state->eval->have_memory_extents = data_extent_union(new_data, state->eval->have_memory_extents);
		if (state->eval->finished) {
			// the new_data was the final read footprint we need
			perform_syscall(state);
		} else {
			// this was a data dependency - either we have the final
			// read footprint and need to request it, or there
			// are more dependencies. In either case, there's more
			// data to come, so fall through
			do_eval_pass(state);
		}

		return state;
	}
}
