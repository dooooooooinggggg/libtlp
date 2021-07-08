#include <stdio.h>
#include <stddef.h>
#include <unistd.h>

typedef signed char s8;
typedef unsigned char u8;
typedef signed short s16;
typedef unsigned short u16;
typedef signed int s32;
typedef unsigned int u32;
typedef signed long long s64;
typedef unsigned long long u64;
typedef int __kernel_key_t;
typedef int __kernel_mqd_t;
typedef unsigned short __kernel_old_uid_t;
typedef unsigned short __kernel_old_gid_t;
typedef unsigned long __kernel_old_dev_t;
typedef long __kernel_long_t;
typedef unsigned long __kernel_ulong_t;
typedef __kernel_ulong_t __kernel_ino_t;
typedef unsigned int __kernel_mode_t;
typedef int __kernel_pid_t;
typedef int __kernel_ipc_pid_t;
typedef unsigned int __kernel_uid_t;
typedef unsigned int __kernel_gid_t;
typedef __kernel_long_t __kernel_suseconds_t;
typedef int __kernel_daddr_t;
typedef unsigned int __kernel_uid32_t;
typedef unsigned int __kernel_gid32_t;
typedef __kernel_ulong_t __kernel_size_t;
typedef __kernel_long_t __kernel_ssize_t;
typedef __kernel_long_t __kernel_ptrdiff_t;
typedef _Bool bool;
typedef unsigned gfp_t;
typedef unsigned slab_flags_t;
typedef unsigned fmode_t;
typedef struct
{
	uid_t val;
} kuid_t;
typedef unsigned int __u32;
typedef struct
{
	int counter;
} atomic_t;
typedef struct qspinlock
{
	union {
		atomic_t val;
		struct
		{
			u8 locked;
			u8 pending;
		};
		struct
		{
			u16 locked_pending;
			u16 tail;
		};
	};
} arch_spinlock_t;
typedef struct cpumask
{
	unsigned long bits[(((8192) + ((sizeof(long) * 8)) - 1) / ((sizeof(long) * 8)))];
} cpumask_t;
typedef struct
{
	int val[2];
} __kernel_fsid_t;
typedef __signed__ char __s8;
typedef unsigned char __u8;
typedef __signed__ short __s16;
typedef unsigned short __u16;
typedef __signed__ int __s32;
typedef __kernel_long_t __kernel_off_t;
typedef long long __kernel_loff_t;
typedef __kernel_long_t __kernel_time_t;
typedef __kernel_time_t time_t;
typedef __kernel_long_t __kernel_clock_t;
typedef int __kernel_timer_t;
typedef int __kernel_clockid_t;
typedef char *__kernel_caddr_t;
typedef unsigned short __kernel_uid16_t;
typedef unsigned short __kernel_gid16_t;
typedef __u16 __le16;
typedef __u16 __be16;
typedef __u32 __le32;
typedef __u32 __be32;
__extension__ typedef unsigned long long __u64;
typedef __u64 __le64;
typedef __u64 __be64;
typedef __u16 __sum16;
typedef __u32 __wsum;
typedef struct seqcount
{
	unsigned sequence;
} seqcount_t;
typedef struct
{
	unsigned long bits[((((1 << 10)) + ((sizeof(long) * 8)) - 1) / ((sizeof(long) * 8)))];
} nodemask_t;
typedef struct raw_spinlock
{
	arch_spinlock_t raw_lock;
} raw_spinlock_t;
typedef struct spinlock
{
	union {
		struct raw_spinlock rlock;
	};
} spinlock_t;
typedef struct
{
	long counter;
} atomic64_t;
typedef atomic64_t atomic_long_t;
typedef s64 ktime_t;
typedef struct
{
	unsigned long seg;
} mm_segment_t;
typedef __kernel_clockid_t clockid_t;
typedef union sigval {
	int sival_int;
	void *sival_ptr;
} sigval_t;
typedef struct siginfo
{
	int si_signo;
	int si_errno;
	int si_code;
	union {
		int _pad[((128 - (4 * sizeof(int))) / sizeof(int))];
		struct
		{
			__kernel_pid_t _pid;
			__kernel_uid32_t _uid;
		} _kill;
		struct
		{
			__kernel_timer_t _tid;
			int _overrun;
			char _pad[sizeof(__kernel_uid32_t) - sizeof(int)];
			sigval_t _sigval;
			int _sys_private;
		} _timer;
		struct
		{
			__kernel_pid_t _pid;
			__kernel_uid32_t _uid;
			sigval_t _sigval;
		} _rt;
		struct
		{
			__kernel_pid_t _pid;
			__kernel_uid32_t _uid;
			int _status;
			__kernel_clock_t _utime;
			__kernel_clock_t _stime;
		} _sigchld;
		struct
		{
			void *_addr;
			short _addr_lsb;
			union {
				struct
				{
					void *_lower;
					void *_upper;
				} _addr_bnd;
				__u32 _pkey;
			};
		} _sigfault;
		struct
		{
			long _band;
			int _fd;
		} _sigpoll;
		struct
		{
			void *_call_addr;
			int _syscall;
			unsigned int _arch;
		} _sigsys;
	} _sifields;
} siginfo_t;

#ifdef __APPLE__
#else
typedef struct
{
	unsigned long sig[(64 / 64)];
} sigset_t;

#endif

enum pid_type
{
	PIDTYPE_PID,
	PIDTYPE_PGID,
	PIDTYPE_SID,
	PIDTYPE_MAX,
	__PIDTYPE_TGID
};
enum
{
	MM_FILEPAGES,
	MM_ANONPAGES,
	MM_SWAPENTS,
	MM_SHMEMPAGES,
	NR_MM_COUNTERS
};
enum perf_event_task_context
{
	perf_invalid_context = -1,
	perf_hw_context = 0,
	perf_sw_context,
	perf_nr_task_contexts,
};
struct list_head
{
	struct list_head *next, *prev;
};
struct thread_info
{
	unsigned long flags;
	u32 status;
};
struct sysv_shm
{
	struct list_head shm_clist;
};
struct llist_head
{
	struct llist_node *first;
};
struct llist_node
{
	struct llist_node *next;
};
struct sched_rt_entity
{
	struct list_head run_list;
	unsigned long timeout;
	unsigned long watchdog_stamp;
	unsigned int time_slice;
	unsigned short on_rq;
	unsigned short on_list;
	struct sched_rt_entity *back;
};
//__attribute__((designated_init));
struct sysv_sem
{
	struct sem_undo_list *undo_list;
};
struct task_cputime
{
	u64 utime;
	u64 stime;
	unsigned long long sum_exec_runtime;
};
struct prev_cputime
{
	u64 utime;
	u64 stime;
	raw_spinlock_t lock;
};
struct sched_avg
{
	u64 last_update_time;
	u64 load_sum;
	u64 runnable_load_sum;
	u32 util_sum;
	u32 period_contrib;
	unsigned long load_avg;
	unsigned long runnable_load_avg;
	unsigned long util_avg;
};
struct sched_statistics
{
	u64 wait_start;
	u64 wait_max;
	u64 wait_count;
	u64 wait_sum;
	u64 iowait_count;
	u64 iowait_sum;
	u64 sleep_start;
	u64 sleep_max;
	s64 sum_sleep_runtime;
	u64 block_start;
	u64 block_max;
	u64 exec_max;
	u64 slice_max;
	u64 nr_migrations_cold;
	u64 nr_failed_migrations_affine;
	u64 nr_failed_migrations_running;
	u64 nr_failed_migrations_hot;
	u64 nr_forced_migrations;
	u64 nr_wakeups;
	u64 nr_wakeups_sync;
	u64 nr_wakeups_migrate;
	u64 nr_wakeups_local;
	u64 nr_wakeups_remote;
	u64 nr_wakeups_affine;
	u64 nr_wakeups_affine_attempts;
	u64 nr_wakeups_passive;
	u64 nr_wakeups_idle;
};
struct rb_node
{
	unsigned long __rb_parent_color;
	struct rb_node *rb_right;
	struct rb_node *rb_left;
} __attribute__((aligned(sizeof(long))));
struct load_weight
{
	unsigned long weight;
	u32 inv_weight;
};
struct sched_entity
{
	struct load_weight load;
	unsigned long runnable_weight;
	struct rb_node run_node;
	struct list_head group_node;
	unsigned int on_rq;
	u64 exec_start;
	u64 sum_exec_runtime;
	u64 vruntime;
	u64 prev_sum_exec_runtime;
	u64 nr_migrations;
	struct sched_statistics statistics;
	int depth;
	struct sched_entity *parent;
	struct cfs_rq *cfs_rq;
	struct cfs_rq *my_q;
	struct sched_avg avg __attribute__((__aligned__((1 << (6)))));
};
struct hlist_head
{
	struct hlist_node *first;
};
struct hlist_node
{
	struct hlist_node *next, **pprev;
};
struct pid_link
{
	struct hlist_node node;
	struct pid *pid;
};

struct sigpending
{
	struct list_head list;
	sigset_t signal;
};
enum timespec_type
{
	TT_NONE = 0,
	TT_NATIVE = 1,
	TT_COMPAT = 2,
};
struct restart_block
{
	long (*fn)(struct restart_block *);
	union {
		struct
		{
			u32 *uaddr;
			u32 val;
			u32 flags;
			u32 bitset;
			u64 time;
			u32 *uaddr2;
		} futex;
		struct
		{
			clockid_t clockid;
			enum timespec_type type;
			union {
				struct timespec *rmtp;
				struct compat_timespec *compat_rmtp;
			};
			u64 expires;
		} nanosleep;
		struct
		{
			struct pollfd *ufds;
			int nfds;
			int has_timeout;
			unsigned long tv_sec;
			unsigned long tv_nsec;
		} poll;
	};
};
struct task_rss_stat
{
	int events;
	int count[NR_MM_COUNTERS];
};
struct vmacache
{
	u64 seqnum;
	struct vm_area_struct *vmas[(1U << 2)];
};
struct seccomp
{
	int mode;
	struct seccomp_filter *filter;
};
struct plist_node
{
	int prio;
	struct list_head prio_list;
	struct list_head node_list;
};
struct sched_info
{
	unsigned long pcount;
	unsigned long long run_delay;
	unsigned long long last_arrival;
	unsigned long long last_queued;
};
struct task_io_accounting
{
	u64 rchar;
	u64 wchar;
	u64 syscr;
	u64 syscw;
	u64 read_bytes;
	u64 write_bytes;
	u64 cancelled_write_bytes;
};
struct rb_root
{
	struct rb_node *rb_node;
};
struct rb_root_cached
{
	struct rb_root rb_root;
	struct rb_node *rb_leftmost;
};
struct wake_q_node
{
	struct wake_q_node *next;
};
struct timerqueue_node
{
	struct rb_node node;
	ktime_t expires;
};
struct hrtimer
{
	struct timerqueue_node node;
	ktime_t _softexpires;
	enum hrtimer_restart (*function)(struct hrtimer *);
	struct hrtimer_clock_base *base;
	u8 state;
	u8 is_rel;
};
struct sched_dl_entity
{
	struct rb_node rb_node;
	u64 dl_runtime;
	u64 dl_deadline;
	u64 dl_period;
	u64 dl_bw;
	u64 dl_density;
	s64 runtime;
	u64 deadline;
	unsigned int flags;
	unsigned int dl_throttled : 1;
	unsigned int dl_boosted : 1;
	unsigned int dl_yielded : 1;
	unsigned int dl_non_contending : 1;
	struct hrtimer dl_timer;
	struct hrtimer inactive_timer;
};
struct optimistic_spin_queue
{
	atomic_t tail;
};
struct mutex
{
	atomic_long_t owner;
	spinlock_t wait_lock;
	struct optimistic_spin_queue osq;
	struct list_head wait_list;
};
struct arch_tlbflush_unmap_batch
{
	struct cpumask cpumask;
};
struct tlbflush_unmap_batch
{
	struct arch_tlbflush_unmap_batch arch;
	bool flush_required;
	bool writable;
};
struct callback_head
{
	struct callback_head *next;
	void (*func)(struct callback_head *head);
} __attribute__((aligned(sizeof(void *))));
struct desc_struct
{
	u16 limit0;
	u16 base0;
	u16 base1 : 8, type : 4, s : 1, dpl : 2, p : 1;
	u16 limit1 : 4, avl : 1, l : 1, d : 1, g : 1, base2 : 8;
} __attribute__((packed));
struct fxregs_state
{
	u16 cwd;
	u16 swd;
	u16 twd;
	u16 fop;
	union {
		struct
		{
			u64 rip;
			u64 rdp;
		};
		struct
		{
			u32 fip;
			u32 fcs;
			u32 foo;
			u32 fos;
		};
	};
	u32 mxcsr;
	u32 mxcsr_mask;
	u32 st_space[32];
	u32 xmm_space[64];
	u32 padding[12];
	union {
		u32 padding1[12];
		u32 sw_reserved[12];
	};
} __attribute__((aligned(16)));
struct xstate_header
{
	u64 xfeatures;
	u64 xcomp_bv;
	u64 reserved[6];
} __attribute__((packed));
struct xregs_state
{
	struct fxregs_state i387;
	struct xstate_header header;
	u8 extended_state_area[0];
} __attribute__((packed, aligned(64)));
struct swregs_state
{
	u32 cwd;
	u32 swd;
	u32 twd;
	u32 fip;
	u32 fcs;
	u32 foo;
	u32 fos;
	u32 st_space[20];
	u8 ftop;
	u8 changed;
	u8 lookahead;
	u8 no_update;
	u8 rm;
	u8 alimit;
	struct math_emu_info *info;
	u32 entry_eip;
};
struct fregs_state
{
	u32 cwd;
	u32 swd;
	u32 twd;
	u32 fip;
	u32 fcs;
	u32 foo;
	u32 fos;
	u32 st_space[20];
	u32 status;
};
union fpregs_state {
	struct fregs_state fsave;
	struct fxregs_state fxsave;
	struct swregs_state soft;
	struct xregs_state xsave;
	u8 __padding[((1UL) << 12)];
};
struct fpu
{
	unsigned int last_cpu;
	unsigned char initialized;
	union fpregs_state state;
};
struct thread_struct
{
	struct desc_struct tls_array[3];
	unsigned long sp;
	unsigned short es;
	unsigned short ds;
	unsigned short fsindex;
	unsigned short gsindex;
	unsigned long fsbase;
	unsigned long gsbase;
	struct perf_event *ptrace_bps[4];
	unsigned long debugreg6;
	unsigned long ptrace_dr7;
	unsigned long cr2;
	unsigned long trap_nr;
	unsigned long error_code;
	unsigned long *io_bitmap_ptr;
	unsigned long iopl;
	unsigned io_bitmap_max;
	mm_segment_t addr_limit;
	unsigned int sig_on_uaccess_err : 1;
	unsigned int uaccess_err : 1;
	struct fpu fpu;
};
struct page_frag
{
	struct page *page;
	__u32 offset;
	__u32 size;
};
struct task_struct
{
	struct thread_info thread_info;
	volatile long state;
	void *stack;
	atomic_t usage;
	unsigned int flags;
	unsigned int ptrace;
	struct llist_node wake_entry;
	int on_cpu;
	unsigned int cpu;
	unsigned int wakee_flips;
	unsigned long wakee_flip_decay_ts;
	struct task_struct *last_wakee;
	int wake_cpu;
	int on_rq;
	int prio;
	int static_prio;
	int normal_prio;
	unsigned int rt_priority;
	const struct sched_class *sched_class;
	struct sched_entity se;
	struct sched_rt_entity rt;
	struct task_group *sched_task_group;
	struct sched_dl_entity dl;
	struct hlist_head preempt_notifiers;
	unsigned int btrace_seq;
	unsigned int policy;
	int nr_cpus_allowed;
	cpumask_t cpus_allowed;
	unsigned long rcu_tasks_nvcsw;
	u8 rcu_tasks_holdout;
	u8 rcu_tasks_idx;
	int rcu_tasks_idle_cpu;
	struct list_head rcu_tasks_holdout_list;
	struct sched_info sched_info;
	struct list_head tasks;
	struct plist_node pushable_tasks;
	struct rb_node pushable_dl_tasks;
	struct mm_struct *mm;
	struct mm_struct *active_mm;
	struct vmacache vmacache;
	struct task_rss_stat rss_stat;
	int exit_state;
	int exit_code;
	int exit_signal;
	int pdeath_signal;
	unsigned long jobctl;
	unsigned int personality;
	unsigned sched_reset_on_fork : 1;
	unsigned sched_contributes_to_load : 1;
	unsigned sched_migrated : 1;
	unsigned sched_remote_wakeup : 1;
	unsigned : 0;
	unsigned in_execve : 1;
	unsigned in_iowait : 1;
	unsigned restore_sigmask : 1;
	unsigned memcg_may_oom : 1;
	unsigned memcg_kmem_skip_account : 1;
	unsigned no_cgroup_migration : 1;
	unsigned long atomic_flags;
	struct restart_block restart_block;
	pid_t pid;
	pid_t tgid;
	unsigned long stack_canary;
	struct task_struct *real_parent;
	struct task_struct *parent;
	struct list_head children;
	struct list_head sibling;
	struct task_struct *group_leader;
	struct list_head ptraced;
	struct list_head ptrace_entry;
	struct pid_link pids[PIDTYPE_MAX];
	struct list_head thread_group;
	struct list_head thread_node;
	struct completion *vfork_done;
	int *set_child_tid;
	int *clear_child_tid;
	u64 utime;
	u64 stime;
	u64 gtime;
	struct prev_cputime prev_cputime;
	unsigned long nvcsw;
	unsigned long nivcsw;
	u64 start_time;
	u64 real_start_time;
	unsigned long min_flt;
	unsigned long maj_flt;
	struct task_cputime cputime_expires;
	struct list_head cpu_timers[3];
	const struct cred *ptracer_cred;
	const struct cred *real_cred;
	const struct cred *cred;
	char comm[16];
	struct nameidata *nameidata;
	struct sysv_sem sysvsem;
	struct sysv_shm sysvshm;
	unsigned long last_switch_count;
	struct fs_struct *fs;
	struct files_struct *files;
	struct nsproxy *nsproxy;
	struct signal_struct *signal;
	struct sighand_struct *sighand;
	sigset_t blocked;
	sigset_t real_blocked;
	sigset_t saved_sigmask;
	struct sigpending pending;
	unsigned long sas_ss_sp;
	size_t sas_ss_size;
	unsigned int sas_ss_flags;
	struct callback_head *task_works;
	struct audit_context *audit_context;
	kuid_t loginuid;
	unsigned int sessionid;
	struct seccomp seccomp;
	u32 parent_exec_id;
	u32 self_exec_id;
	spinlock_t alloc_lock;
	raw_spinlock_t pi_lock;
	struct wake_q_node wake_q;
	struct rb_root_cached pi_waiters;
	struct task_struct *pi_top_task;
	struct rt_mutex_waiter *pi_blocked_on;
	void *journal_info;
	struct bio_list *bio_list;
	struct blk_plug *plug;
	struct reclaim_state *reclaim_state;
	struct backing_dev_info *backing_dev_info;
	struct io_context *io_context;
	unsigned long ptrace_message;
	siginfo_t *last_siginfo;
	struct task_io_accounting ioac;
	u64 acct_rss_mem1;
	u64 acct_vm_mem1;
	u64 acct_timexpd;
	nodemask_t mems_allowed;
	seqcount_t mems_allowed_seq;
	int cpuset_mem_spread_rotor;
	int cpuset_slab_spread_rotor;
	struct css_set *cgroups;
	struct list_head cg_list;
	u32 closid;
	u32 rmid;
	struct robust_list_head *robust_list;
	struct compat_robust_list_head *compat_robust_list;
	struct list_head pi_state_list;
	struct futex_pi_state *pi_state_cache;
	struct perf_event_context *perf_event_ctxp[perf_nr_task_contexts];
	struct mutex perf_event_mutex;
	struct list_head perf_event_list;
	struct mempolicy *mempolicy;
	short il_prev;
	short pref_node_fork;
	int numa_scan_seq;
	unsigned int numa_scan_period;
	unsigned int numa_scan_period_max;
	int numa_preferred_nid;
	unsigned long numa_migrate_retry;
	u64 node_stamp;
	u64 last_task_numa_placement;
	u64 last_sum_exec_runtime;
	struct callback_head numa_work;
	struct list_head numa_entry;
	struct numa_group *numa_group;
	unsigned long *numa_faults;
	unsigned long total_numa_faults;
	unsigned long numa_faults_locality[3];
	unsigned long numa_pages_migrated;
	struct tlbflush_unmap_batch tlb_ubc;
	struct callback_head rcu;
	struct pipe_inode_info *splice_pipe;
	struct page_frag task_frag;
	struct task_delay_info *delays;
	int nr_dirtied;
	int nr_dirtied_pause;
	unsigned long dirty_paused_when;
	u64 timer_slack_ns;
	u64 default_timer_slack_ns;
	int curr_ret_stack;
	int curr_ret_depth;
	struct ftrace_ret_stack *ret_stack;
	unsigned long long ftrace_timestamp;
	atomic_t trace_overrun;
	atomic_t tracing_graph_pause;
	unsigned long trace;
	unsigned long trace_recursion;
	struct mem_cgroup *memcg_in_oom;
	gfp_t memcg_oom_gfp_mask;
	int memcg_oom_order;
	unsigned int memcg_nr_pages_over_high;
	struct uprobe_task *utask;
	unsigned int sequential_io;
	unsigned int sequential_io_avg;
	int pagefault_disabled;
	struct task_struct *oom_reaper_list;
	struct vm_struct *stack_vm_area;
	atomic_t stack_refcount;
	int patch_state;
	void *security;
	struct thread_struct thread;
};
int main()
{
	size_t size = sizeof(struct task_struct);
	printf("task_struct size: %lu\n\n", size);

	size_t offset;
	offset = offsetof(struct task_struct, state);
	printf("state: %zu\n", offset);
	offset = offsetof(struct task_struct, pid);
	printf("pid: %zu\n", offset);
	offset = offsetof(struct task_struct, children);
	printf("children: %zu\n", offset);
	offset = offsetof(struct task_struct, sibling);
	printf("sibling: %zu\n", offset);
	offset = offsetof(struct task_struct, comm);
	printf("comm: %zu\n", offset);
	offset = offsetof(struct task_struct, real_parent);
	printf("real_parent: %zu\n", offset);

	return 0;
}
