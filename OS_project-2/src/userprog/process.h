#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "threads/synch.h"
#include <list.h>

typedef int pid_t;

struct process
{
	pid_t pid;

	struct child_process *child_rec;
	struct list open_files;
	struct list children;
	struct semaphore wait_for_child;
	bool child_launched;
};

struct child_process
{
	struct list_elem child_elem;

	pid_t pid;
	// used to set child_rec to NULL when parent exits
	struct process *proc;
	// used to notify parent that child exited
	struct semaphore exited;
	int exit_value;
};

void process_init (void);

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

#endif /* userprog/process.h */
