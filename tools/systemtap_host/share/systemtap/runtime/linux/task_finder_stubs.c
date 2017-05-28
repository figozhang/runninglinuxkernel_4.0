#ifndef TASK_FINDER_STUBS_C
#define TASK_FINDER_STUBS_C

/* Stubs of last resort for when utrace type functionality is not
   available. Nothing should actually work, but things compile
   properly, and silently return dummy data or noisily fail as
   appropriate. */

static void stap_task_finder_unavailable(void) {
  _stp_error("process-tracking is not available in this kernel"
             " [man error::process-tracking]");
}

struct stap_task_finder_target;

typedef int (*stap_task_finder_callback)(struct stap_task_finder_target *tgt,
					 struct task_struct *tsk,
					 int register_p,
					 int process_p);

typedef int
(*stap_task_finder_mmap_callback)(struct stap_task_finder_target *tgt,
				  struct task_struct *tsk,
				  char *path,
				  struct dentry *dentry,
				  unsigned long addr,
				  unsigned long length,
				  unsigned long offset,
				  unsigned long vm_flags);
typedef int
(*stap_task_finder_munmap_callback)(struct stap_task_finder_target *tgt,
				    struct task_struct *tsk,
				    unsigned long addr,
				    unsigned long length);

typedef int
(*stap_task_finder_mprotect_callback)(struct stap_task_finder_target *tgt,
				      struct task_struct *tsk,
				      unsigned long addr,
				      unsigned long length,
				      int prot);

struct stap_task_finder_target {
/* private: */
	struct list_head list;		/* __stp_task_finder_list linkage */
	struct list_head callback_list_head;
	struct list_head callback_list;
	// struct utrace_engine_ops ops;
	size_t pathlen;
	unsigned engine_attached:1;
	unsigned mmap_events:1;
	unsigned munmap_events:1;
	unsigned mprotect_events:1;

/* public: */
	pid_t pid;
	const char *procname;
        const char *purpose;
	stap_task_finder_callback callback;
	stap_task_finder_mmap_callback mmap_callback;
	stap_task_finder_munmap_callback munmap_callback;
	stap_task_finder_mprotect_callback mprotect_callback;
};

static int
stap_register_task_finder_target(struct stap_task_finder_target *new_tgt)
{
  /* do not actually register anything -- callbacks will be ignored */
  _stp_warn("cannot track target in process '%s'", new_tgt->procname);
  return 0;
}

static int
stap_start_task_finder(void)
{
  _stp_warn("process-tracking is not available in this kernel"
            " [man error::process-tracking]");

  return 0;
}

static void
stap_task_finder_post_init(void)
{
  ;
}

static void
stap_stop_task_finder(void)
{
  ;
}

#endif  /* TASK_FINDER_STUBS_C */
