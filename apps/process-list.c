#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <libtlp.h>
#include "azkaban.h"

#ifdef __APPLE__
#define _AC(X, Y) X
#else
#include <linux/const.h>
#endif

/* from include/linux/sched.h*/
/* Used in tsk->state: */
#define TASK_RUNNING 0x0000
#define TASK_INTERRUPTIBLE 0x0001
#define TASK_UNINTERRUPTIBLE 0x0002
#define __TASK_STOPPED 0x0004
#define __TASK_TRACED 0x0008
/* Used in tsk->exit_state: */
#define EXIT_DEAD 0x0010
#define EXIT_ZOMBIE 0x0020
#define EXIT_TRACE (EXIT_ZOMBIE | EXIT_DEAD)
/* Used in tsk->state again: */
#define TASK_PARKED 0x0040
#define TASK_DEAD 0x0080
#define TASK_WAKEKILL 0x0100
#define TASK_WAKING 0x0200
#define TASK_NOLOAD 0x0400
#define TASK_NEW 0x0800
#define TASK_STATE_MAX 0x1000

/*
* ここまでOK
*/

char state_to_char(long state)
{
	switch (state & 0x00FF)
	{
	case TASK_RUNNING:
		return 'R';
	case TASK_INTERRUPTIBLE:
		return 'S';
	case TASK_UNINTERRUPTIBLE:
		return 'D';
	case __TASK_STOPPED:
	case __TASK_TRACED:
		return 'T';
	case TASK_DEAD:
		return 'X';
	default:
		return 'u';
	}
}

struct list_head
{
	struct list_head *next, *prev;
};

/* task struct offset */

/*
* upa env
*/
// #define OFFSET_HEAD_STATE 16
// #define OFFSET_HEAD_PID 2216
// #define OFFSET_HEAD_CHILDREN 2240
// #define OFFSET_HEAD_SIBLING 2256
// #define OFFSET_HEAD_COMM 2632
// #define OFFSET_HEAD_REAL_PARENT 2224

/*
* tatsu env
*/
#define OFFSET_HEAD_STATE 16
#define OFFSET_HEAD_PID 2216
#define OFFSET_HEAD_CHILDREN 2248
#define OFFSET_HEAD_SIBLING 2264
#define OFFSET_HEAD_COMM 2640
#define OFFSET_HEAD_REAL_PARENT 2232

#define TASK_COMM_LEN 16

struct task_struct
{
	uintptr_t vhead, phead;
	uintptr_t vstate, pstate;
	uintptr_t vpid, ppid;
	uintptr_t vchildren, pchildren;
	uintptr_t vsibling, psibling;
	uintptr_t vcomm, pcomm;
	uintptr_t vreal_parent, preal_parent;

	struct list_head children;
	struct list_head sibling;

	uintptr_t children_next;
	uintptr_t children_prev;
	uintptr_t sibling_next;
	uintptr_t sibling_prev;

	uintptr_t real_parent;
};

#define print_task_value(t, name) \
	printf(#name "  %#lx %#lx\n", t->v##name, t->p##name)

/*
* ここまでOK
*/

void dump_task_struct(struct task_struct *t)
{
	print_task_value(t, head);
	print_task_value(t, state);
	print_task_value(t, pid);
	print_task_value(t, children);
	print_task_value(t, sibling);
	print_task_value(t, comm);
	print_task_value(t, real_parent);

	printf("children_next %#lx %#lx\n",
		   t->children_next, __phys_addr_nodebug(t->children_next));
	printf("children_prev %#lx %#lx\n",
		   t->children_prev, __phys_addr_nodebug(t->children_prev));
	printf("sibling_next %#lx %#lx\n",
		   t->sibling_next, __phys_addr_nodebug(t->sibling_next));
	printf("sibling_prev %#lx %#lx\n",
		   t->sibling_prev, __phys_addr_nodebug(t->sibling_prev));
}

#define check_task_value(t, name)                                \
	do                                                           \
	{                                                            \
		if (t->v##name == 0)                                     \
		{                                                        \
			fprintf(stderr,                                      \
					"failed to get address of v" #name           \
					" %#lx\n",                                   \
					t->v##name);                                 \
			return -1;                                           \
		}                                                        \
		if (t->p##name == 0)                                     \
		{                                                        \
			fprintf(stderr,                                      \
					"failed to get physical address for p" #name \
					" from %#lx\n",                              \
					t->v##name);                                 \
			return -1;                                           \
		}                                                        \
	} while (0)

int fill_task_struct(struct nettlp *nt, uintptr_t vhead, struct task_struct *t)
{
	int ret;

	t->vhead = vhead;
	t->phead = __phys_addr_nodebug(t->vhead);
	t->vstate = vhead + OFFSET_HEAD_STATE;
	t->pstate = __phys_addr_nodebug(t->vstate);
	t->vpid = vhead + OFFSET_HEAD_PID;
	t->ppid = __phys_addr_nodebug(t->vpid);
	t->vchildren = vhead + OFFSET_HEAD_CHILDREN;
	t->pchildren = __phys_addr_nodebug(t->vchildren);
	t->vsibling = vhead + OFFSET_HEAD_SIBLING;
	t->psibling = __phys_addr_nodebug(t->vsibling);
	t->vcomm = vhead + OFFSET_HEAD_COMM;
	t->pcomm = __phys_addr_nodebug(t->vcomm);
	t->vreal_parent = vhead + OFFSET_HEAD_REAL_PARENT;
	t->preal_parent = __phys_addr_nodebug(t->vreal_parent);

	// printf("=========================\n");
	// printf("t->vhead: %lu\n", t->vhead);
	// printf("t->phead: %lu\n", t->phead);
	// printf("t->vstate: %lu\n", t->vstate);
	// printf("t->pstate: %lu\n", t->pstate);
	// printf("t->vpid: %lu\n", t->vpid);
	// printf("t->ppid: %lu\n", t->ppid);
	// printf("t->vchildren: %lu\n", t->vchildren);
	// printf("t->pchildren : %lu\n", t->pchildren);
	// printf("t->vsibling: %lu\n", t->vsibling);
	// printf("t->psibling: %lu\n", t->psibling);
	// printf("t->vcomm: %lu\n", t->vcomm);
	// printf("t->pcomm: %lu\n", t->pcomm);
	// printf("t->vreal_parent: %lu\n", t->vreal_parent);
	// printf("t->preal_parent: %lu\n", t->preal_parent);
	// printf("=========================\n");

	ret = dma_read(nt, t->pchildren, &t->children, sizeof(t->children));
	if (ret < sizeof(t->children))
		return -1;

	ret = dma_read(nt, t->psibling, &t->sibling, sizeof(t->sibling));
	if (ret < sizeof(t->sibling))
		return -1;

	ret = dma_read(nt, t->preal_parent, &t->real_parent, sizeof(t->real_parent));
	if (ret < sizeof(t->real_parent))
		return -1;

	t->children_next = (uintptr_t)t->children.next;
	t->children_prev = (uintptr_t)t->children.prev;
	t->sibling_next = (uintptr_t)t->sibling.next;
	t->sibling_prev = (uintptr_t)t->sibling.prev;

	check_task_value(t, head);
	check_task_value(t, pid);
	check_task_value(t, children);
	check_task_value(t, sibling);
	check_task_value(t, comm);

	return 0;
}

void print_task_struct_column(void)
{
	printf("PhyAddr             PID STAT COMMAND\n");
}

int print_task_struct(struct nettlp *nt, struct task_struct t)
{
	int ret, pid;
	long state;
	char comm[TASK_COMM_LEN];

	ret = dma_read(nt, t.ppid, &pid, sizeof(pid));
	if (ret < sizeof(pid))
	{
		fprintf(stderr, "failed to read pid from %#lx\n", t.ppid);
		return -1;
	}

	ret = dma_read(nt, t.pcomm, &comm, sizeof(comm));
	if (ret < sizeof(comm))
	{
		fprintf(stderr, "failed to read comm from %#lx\n", t.pcomm);
		return -1;
	}

	ret = dma_read(nt, t.pstate, &state, sizeof(state));
	if (ret < sizeof(state))
	{
		fprintf(stderr, "failed to read state from %#lx\n", t.pstate);
		return -1;
	}

	comm[TASK_COMM_LEN - 1] = '\0'; /* preventing overflow */

	printf("%#016lx %6u %c: %s\n", t.phead, pid, state_to_char(state), comm);

	return 0;
}

int task(struct nettlp *nt, uintptr_t vhead, uintptr_t parent)
{
	/*
	 * vhead is kernel virtual address of task_struct.
	 * parent is the vaddr of the parent's task_struct.
	 */

	int ret;
	struct task_struct t;

	ret = fill_task_struct(nt, vhead, &t);
	if (ret < 0)
	{
		fprintf(stderr, "failed to fill task_struct from %#lx\n",
				vhead);
		return ret;
	}

	/* print myself */
	ret = print_task_struct(nt, t);
	if (ret < 0)
		return ret;

	if (t.children_next != t.vchildren)
	{
		/* this task_struct has children. walk them */
		ret = task(nt, t.children_next - OFFSET_HEAD_SIBLING, t.vhead);
		if (ret < 0)
			return ret;
	}

	if (t.sibling_next - OFFSET_HEAD_SIBLING == parent ||
		t.sibling_next - OFFSET_HEAD_CHILDREN == parent)
	{
		/* walk done of the siblings spawned from the parent */
		return 0;
	}

	/* goto the next sibling */
	return task(nt, t.sibling_next - OFFSET_HEAD_SIBLING, parent);
}

uintptr_t find_init_task_from_systemmap(char *map)
{
	FILE *fp;
	char buf[4096];
	uintptr_t addr = 0;

	fp = fopen(map, "r");
	if (!fp)
	{
		perror("fopen");
		return 0;
	}

	while (fgets(buf, sizeof(buf), fp) != NULL)
	{
		if (strstr(buf, "D init_task"))
		{
			char *p;
			p = strchr(buf, ' ');
			*p = '\0';
			addr = strtoul(buf, NULL, 16);
			break;
		}
	}

	fclose(fp);

	return addr;
}

void usage(void)
{
	printf("./process-list -s System.map"
		   "usage\n"
		   //    "    -r remote addr\n"
		   //    "    -l local addr\n"
		   //    "    -R remote host addr to get requester id\n"
		   //    "    -b bus number, XX:XX (exclusive with -R)\n"
		   "    -t tag\n"
		   "    -s path to System.map\n");
}

int main(int argc, char **argv)
{
	int ret, ch;
	struct nettlp nt;
	struct in_addr remote_host;
	uintptr_t addr;
	uint16_t busn, devn;
	struct task_struct t;
	char *map;

	/*
	* init
	*/

	memset(&nt, 0, sizeof(nt));
	addr = 0;
	busn = 0;
	devn = 0;
	map = NULL;

	// b option
	ret = sscanf("02:00", "%hx:%hx", &busn, &devn);
	nt.requester = (busn << 8 | devn);

	// r option
	ret = inet_pton(AF_INET, "192.168.10.1", &nt.remote_addr);
	if (ret < 1)
	{
		perror("inet_pton");
		return -1;
	}

	// l option
	ret = inet_pton(AF_INET, "192.168.10.3", &nt.local_addr);
	if (ret < 1)
	{
		perror("inet_pton");
		return -1;
	}

	// // R option
	// ret = inet_pton(AF_INET, "192.168.10.1", &remote_host);
	// if (ret < 1)
	// {
	// 	perror("inet_pton");
	// 	return -1;
	// }

	// nt.requester = nettlp_msg_get_dev_id(remote_host);

	ret = nettlp_init(&nt);
	if (ret < 0)
	{
		perror("nettlp_init");
		return ret;
	}

	/*
	* / init
	*/

	if (argc != 2)
	{
		printf("%s 0xaddr\n", argv[0]);
		return -1;
	}

	// addr = (unsigned long)0xffffffff82413480; // init_task 一旦決め打ち
	sscanf(argv[1], "0x%lx", &addr);

	if (addr == 0)
	{
		fprintf(stderr, "init_task not found on System.map %s\n", map);
		return -1;
	}

	printf("init_vm_addr: 0x%lx\n", addr);

	fill_task_struct(&nt, addr, &t);

	print_task_struct_column();
	task(&nt, t.vhead, t.vhead);
	//print_task_struct(&nt, t);
	//dump_task_struct(&t);

	return 0;
}
