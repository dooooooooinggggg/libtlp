#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <linux/const.h>

#include <libtlp.h>


/* from arch_x86/include/asm/page_64_types.h */
#define KERNEL_IMAGE_SIZE	(512 * 1024 * 1024)
//#define __PAGE_OFFSET_BASE      _AC(0xffff880000000000, UL)
#define __PAGE_OFFSET_BASE      _AC(0xffff888000000000, UL)
#define __PAGE_OFFSET           __PAGE_OFFSET_BASE
#define __START_KERNEL_map      _AC(0xffffffff80000000, UL)



/* from arch/x86/include/asm/page_types.h */
#define PAGE_OFFSET	((unsigned long)__PAGE_OFFSET)

#define phys_base	0x1000000	/* x86 */

/* from arch/x86/mm/physaddr.c */
unsigned long __phys_addr(unsigned long x)
{
	unsigned long y = x - __START_KERNEL_map;

	/* use the carry flag to determine if x was < __START_KERNEL_map */
	if (x > y) {
		return 0;
		//x = y + phys_base;

		//if (y >= KERNEL_IMAGE_SIZE)
		//return 0;
	} else {
		x = y + (__START_KERNEL_map - PAGE_OFFSET);

		/* carry flag will be set if starting x was >= PAGE_OFFSET */
		//VIRTUAL_BUG_ON((x > y) || !phys_addr_valid(x));
	}

	return x;
}



/* from include/linux/sched.h*/
/* Used in tsk->state: */
#define TASK_RUNNING                    0x0000
#define TASK_INTERRUPTIBLE              0x0001
#define TASK_UNINTERRUPTIBLE            0x0002
#define __TASK_STOPPED                  0x0004
#define __TASK_TRACED                   0x0008
/* Used in tsk->exit_state: */
#define EXIT_DEAD                       0x0010
#define EXIT_ZOMBIE                     0x0020
#define EXIT_TRACE                      (EXIT_ZOMBIE | EXIT_DEAD)
/* Used in tsk->state again: */
#define TASK_PARKED                     0x0040
#define TASK_DEAD                       0x0080
#define TASK_WAKEKILL                   0x0100
#define TASK_WAKING                     0x0200
#define TASK_NOLOAD                     0x0400
#define TASK_NEW                        0x0800
#define TASK_STATE_MAX                  0x1000

char state_to_char(long state)
{
	switch(state &0x00FF) {
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


struct list_head {
	struct list_head *next, *prev;
};


/* task struct offset */
#define OFFSET_HEAD_STATE	16
#define OFFSET_HEAD_PID		2216
#define OFFSET_HEAD_CHILDREN	2240
#define OFFSET_HEAD_SIBLING	2256
#define OFFSET_HEAD_COMM	2632


#define TASK_COMM_LEN		16

struct task_struct {
	uintptr_t	vhead, phead;
	uintptr_t	vstate, pstate;
	uintptr_t	vpid, ppid;
	uintptr_t	vchildren, pchildren;
	uintptr_t	vsibling, psibling;
	uintptr_t	vcomm, pcomm;

	struct list_head children;
	struct list_head sibling;

	uintptr_t	children_next;
	uintptr_t	children_prev;
	uintptr_t	sibling_next;
	uintptr_t	sibling_prev;
};

#define print_task_value(t, name) \
	printf(#name "  %#lx %#lx\n", t->v##name, t->p##name)

void dump_task_struct(struct task_struct *t)
{
	print_task_value(t, head);
	print_task_value(t, state);
	print_task_value(t, pid);
	print_task_value(t, children);
	print_task_value(t, sibling);
	print_task_value(t, comm);

	printf("children_next %#lx %#lx\n",
	       t->children_next, __phys_addr(t->children_next));
	printf("children_prev %#lx %#lx\n",
	       t->children_prev, __phys_addr(t->children_prev));
	printf("sibling_next %#lx %#lx\n",
	       t->sibling_next, __phys_addr(t->sibling_next));
	printf("sibling_prev %#lx %#lx\n",
	       t->sibling_prev, __phys_addr(t->sibling_prev));
}

#define check_task_value(t, name)					\
	do {								\
		if(t->v##name == 0) {					\
			fprintf(stderr,					\
				"failed to get address of v" #name	\
				" %#lx\n", t->v##name);			\
			return -1;					\
		}							\
		if(t->p##name == 0) {					\
			fprintf(stderr,					\
				"failed to get physical address for p"	\
				#name					\
				" from %#lx\n", t->v##name);		\
			return -1;					\
		}							\
	} while(0)							\


int fill_task_struct(struct nettlp *nt, uintptr_t vhead,
		     struct task_struct *t)
{
	int ret;

	t->vhead = vhead;
	t->phead = __phys_addr(t->vhead);
	t->vstate = vhead + OFFSET_HEAD_STATE;
	t->pstate = __phys_addr(t->vstate);
	t->vpid = vhead + OFFSET_HEAD_PID;
	t->ppid = __phys_addr(t->vpid);
	t->vchildren = vhead + OFFSET_HEAD_CHILDREN;
	t->pchildren = __phys_addr(t->vchildren);
	t->vsibling = vhead + OFFSET_HEAD_SIBLING;
	t->psibling = __phys_addr(t->vsibling);
	t->vcomm = vhead + OFFSET_HEAD_COMM;
	t->pcomm = __phys_addr(t->vcomm);

	ret = dma_read(nt, t->pchildren, &t->children, sizeof(t->children));
	if (ret < sizeof(t->children))
		return -1;

	ret = dma_read(nt, t->psibling, &t->sibling, sizeof(t->children));
	if (ret < sizeof(t->sibling))
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
	printf("PhyAddr        PID STAT        COMMAND\n");
}
	

void print_task_struct(struct nettlp *nt, struct task_struct t)
{
	int ret, pid;
	long state;
	char comm[TASK_COMM_LEN];

	ret = dma_read(nt, t.ppid, &pid, sizeof(pid));
	if (ret < sizeof(pid)) {
		fprintf(stderr, "failed to read pid from %#lx\n", t.ppid);
		return;
	}

	ret = dma_read(nt, t.pcomm, &comm, sizeof(comm));
	if (ret < sizeof(comm)) {
		fprintf(stderr, "failed to read comm from %#lx\n", t.pcomm);
		return;
	}

	ret = dma_read(nt, t.pstate, &state, sizeof(state));
	if (ret < sizeof(state)) {
		fprintf(stderr, "failed to read state from %#lx\n", t.pstate);
		return;
	}

	comm[TASK_COMM_LEN - 1] = '\0';	/* preventing overflow */

	printf("%#lx %6d    %c 0x%04lx %s\n",
	       t.phead, pid, state_to_char(state), state, comm);
}



int task(struct nettlp *nt, uintptr_t vhead, uintptr_t children)
{
	/*
	 * vhead is kernel virtual address of task_struct.
	 * children is the vaddr of the parent's struct list_head children.
	 */

	int ret;
	struct task_struct t;
	
	ret = fill_task_struct(nt, vhead, &t);
	if (ret < 0) {
		fprintf(stderr, "failed to fill task_struct from %#lx\n",
			vhead);
		return ret;
	}
	
	/* print myself */
	print_task_struct(nt, t);

	if (t.children_next != t.vchildren) {
		/* this task_struct has children. walk them  */
		ret = task(nt, t.children_next - OFFSET_HEAD_SIBLING,
			   t.vchildren);
		if (ret < 0)
			return ret;
	}
	
	if (children == t.sibling_next) {
		/* walk done of the siblings spawned from the parent */
		return 0;
	}

	/* goto the next sibling */
	return task(nt, t.sibling_next - OFFSET_HEAD_SIBLING, children);
}

void usage(void)
{
	printf("usage\n"
	       "    -r remote addr\n"
	       "    -l local addr\n"
	       "    -R remote port (default 14198)\n"
	       "    -L local port (default 14198)\n"
	       "    -b bus number, XX:XX\n"
	       "    -t tag\n"
	       "    -a virtual address of the first task_struct\n"
	);
}


int main(int argc, char **argv)
{
	int ret, ch;
	struct nettlp nt;
	uintptr_t addr;
	uint16_t busn, devn;
	struct task_struct t;

	memset(&nt, 0, sizeof(nt));
	nt.remote_port = 14198;
	nt.local_port = 14198;
	addr = 0;
	busn = 0;
	devn = 0;

	while ((ch = getopt(argc, argv, "r:l:R:L:b:t:a:")) != -1) {
		switch (ch) {
		case 'r':
			ret = inet_pton(AF_INET, optarg, &nt.remote_addr);
			if (ret < 1) {
				perror("inet_pton");
				return -1;
			}
			break;

		case 'l':
			ret = inet_pton(AF_INET, optarg, &nt.local_addr);
			if (ret < 1) {
				perror("inet_pton");
				return -1;
			}
			break;

		case 'R':
			nt.remote_port = atoi(optarg);
			break;

		case 'L':
			nt.local_port = atoi(optarg);
			break;

		case 'b':
			ret = sscanf(optarg, "%hx:%hx", &busn, &devn);
			nt.requester = (busn << 8 | devn);
			break;

		case 't':
			nt.tag = atoi(optarg);
			break;

		case 'a':
			ret = sscanf(optarg, "0x%lx", &addr);
			break;

		default :
			usage();
			return -1;
		}
	}


	ret = nettlp_init(&nt);
	if (ret < 0) {
		perror("nettlp_init");
		return ret;
	}

	fill_task_struct(&nt, addr, &t);

	print_task_struct_column();
	task(&nt, t.vhead, t.vchildren);
	//print_task_struct(&nt, t);
	//dump_task_struct(&t);

	return 0;
}