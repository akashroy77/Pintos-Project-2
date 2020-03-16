#include "threads/thread.h"
#include "devices/timer.h"
#include <stddef.h>
#include <random.h>
#include <stdio.h>
#include <string.h>
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/intr-stubs.h"
#include "threads/palloc.h"
#include "threads/switch.h"
#include "threads/synch.h"
#include "threads/vaddr.h"

#ifdef USERPROG
#include "userprog/process.h"
#endif

/* Random value for struct thread's `magic' member.
   Used to detect stack overflow.  See the big comment at the top
   of thread.h for details. */
#define THREAD_MAGIC 0xcd6abf4b

/* List of processes in THREAD_READY state, that is, processes
   that are ready to run but not actually running. */
static struct list ready_list;

/* List of all processes.  Processes are added to this list
   when they are first scheduled and removed when they exit. */
static struct list all_list;

/* Idle thread. */
static struct thread *idle_thread;

/* Initial thread, the thread running init.c:main(). */
static struct thread *initial_thread;

/* Lock used by allocate_tid(). */
static struct lock tid_lock;

/* variable that contains the size of the ready queue */
static int number_ready_threads = 0;

/*variable that stores the load_avg of the current thread */
static fixed_point_t load_avg = 0;
static fixed_point_t load_avg_coef = 0;

/* Stack frame for kernel_thread(). */
struct kernel_thread_frame 
  {
    void *eip;                  /* Return address. */
    thread_func *function;      /* Function to call. */
    void *aux;                  /* Auxiliary data for function. */
  };

/* Statistics. */
static long long idle_ticks;    /* # of timer ticks spent idle. */
static long long kernel_ticks;  /* # of timer ticks in kernel threads. */
static long long user_ticks;    /* # of timer ticks in user programs. */

/* Scheduling. */
#define TIME_SLICE 4            /* # of timer ticks to give each thread. */
static unsigned thread_ticks;   /* # of timer ticks since last yield. */

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
bool thread_mlfqs;
bool thread_donation_enabled;

static void kernel_thread (thread_func *, void *aux);

static void idle (void *aux UNUSED);
static struct thread *running_thread (void);
static struct thread *next_thread_to_run (void);
static void init_thread (struct thread *, const char *name, int priority);
static bool is_thread (struct thread *) UNUSED;
static void *alloc_frame (struct thread *, size_t size);
static void schedule (void);
void thread_schedule_tail (struct thread *prev);

static void thread_calc_prio_mlfqs (struct thread *t);

static tid_t allocate_tid (void);

void update_recent_cpu_of (struct thread *t, void *aux UNUSED);
static void update_load_avg (void);

/*
MLFQS queues
cur and next are used to keep track of current thread's priority 
and next-in-line thread priority to save time in next_thread_to_run
*/
struct priority_queue{
    struct list queue[PRI_TOTAL];
    int max;
    struct lock q_lock;
  };

struct priority_queue priority_q;

static void
priority_q_init (void)
{
  for (int i=0; i < PRI_TOTAL; i++)
    list_init( &priority_q.queue[i]);
  priority_q.max = PRI_DEFAULT;
  lock_init (&priority_q.q_lock);
};

static void 
priority_q_enqueue (struct thread *t)
{
  ASSERT (intr_get_level () == INTR_OFF);
  ASSERT (t->status == THREAD_READY);

  int push_to = thread_get_priority_of (t);
  list_push_back (&priority_q.queue[push_to], &t->ready_elem);
  priority_q.max = MAX(push_to, priority_q.max);
};

/* Initializes the threading system by transforming the code
   that's currently running into a thread.  This can't work in
   general and it is possible in this case only because loader.S
   was careful to put the bottom of the stack at a page boundary.

   Also initializes the run queue and the tid lock.

   After calling this function, be sure to initialize the page
   allocator before trying to create any threads with
   thread_create().

   It is not safe to call thread_current() until this function
   finishes. */
void
thread_init (void) 
{
  ASSERT (intr_get_level () == INTR_OFF);
  thread_donation_enabled = false;
  load_avg = 0;

  lock_init (&tid_lock);
  // list_init (&ready_list);
  priority_q_init ();
  list_init (&all_list);
  
  #ifdef USERPROG
  list_init (&all_proc);
  #endif

  /* Set up a thread structure for the  thread. */
  initial_thread = running_thread ();
  init_thread (initial_thread, "main", PRI_DEFAULT);
  // because we do not have locks yet - doing it manually

  initial_thread->status = THREAD_RUNNING;
  initial_thread->tid = allocate_tid ();
}

/* Starts preemptive thread scheduling by enabling interrupts.
   Also creates the idle thread. */
void
thread_start (void) 
{
  /* Create the idle thread. */
  thread_donation_enabled = !thread_mlfqs;
  struct semaphore idle_started;
  sema_init (&idle_started, 0);
  thread_create ("idle", PRI_MIN, idle, &idle_started);

  /* Start preemptive thread scheduling. */
  intr_enable ();

  /* Wait for the idle thread to initialize idle_thread. */
  sema_down (&idle_started);
  printf("Threading initialized\n");
}

/* Called every second to update recent_cpu and load_avg for all threads */

void
update_recent_cpu_of (struct thread *t, void *aux)
{
  fixed_point_t temp;
  temp = fp_mul (load_avg_coef, t->recent_cpu);
  t->recent_cpu = fp_add(temp, int_to_fp (t->nice));
}

static void
update_load_avg ()
{
  fixed_point_t t1, t2;
  t1 = fp_mul ( N59OF60, load_avg);
  t2 = int_div (number_ready_threads, 60);

  load_avg = fp_add (t1, t2);
}

/* Called by the timer interrupt handler at each timer tick.
   Thus, this function runs in an external interrupt context. */
void
thread_tick (int64_t ticks)
{
  fixed_point_t t1, t2;     // used to precompule load_avg coefficient
  ASSERT (intr_context ()); // only called inside an external interrupt
  struct thread *t = thread_current ();

  /* Update statistics. */
  if (t == idle_thread)
    idle_ticks++;
#ifdef USERPROG
  else if (t->pagedir != NULL)
    user_ticks++;
#endif
  else
    kernel_ticks++;

  if (thread_mlfqs)
  {
    /* every tick increase the recent_cpu time by 1*/
    if (t != idle_thread)
      t->recent_cpu = fp_add (t->recent_cpu, FP_ONE);
      
    /* priority gets calculated every 4th tick */
    if (ticks % 4 == 0){
      thread_calc_prio_mlfqs (t);
      if (thread_get_priority () < priority_q.max)
        intr_yield_on_return ();
    }

    /* recalculating load_avg and recent_cpu every second */
    if (ticks % TIMER_FREQ == 0)
      {
        update_load_avg ();

        t1 = fp_int_mul (load_avg, 2);
        t2 = fp_add (t1, FP_ONE);
        load_avg_coef = fp_div (t1, t2);
  
        thread_foreach (update_recent_cpu_of, NULL);
      }
  }
  
  /* Enforce preemption. */
  if (++thread_ticks >= TIME_SLICE)
    intr_yield_on_return ();
}

/* Prints thread statistics. */
void
thread_print_stats (void) 
{
  printf ("Thread: %lld idle ticks, %lld kernel ticks, %lld user ticks\n",
          idle_ticks, kernel_ticks, user_ticks);
}

/* Creates a new kernel thread named NAME with the given initial
   PRIORITY, which executes FUNCTION passing AUX as the argument,
   and adds it to the ready queue.  Returns the thread identifier
   for the new thread, or TID_ERROR if creation fails.

   If thread_start() has been called, then the new thread may be
   scheduled before thread_create() returns.  It could even exit
   before thread_create() returns.  Contrariwise, the original
   thread may run for any amount of time before the new thread is
   scheduled.  Use a semaphore or some other form of
   synchronization if you need to ensure ordering.

   The code provided sets the new thread's `priority' member to
   PRIORITY, but no actual priority scheduling is implemented.
   priority scheduling is the goal of Problem 1-3. */

/* TODO: handle priority_queue */
/* Akash */

tid_t
thread_create (const char *name, int priority,
               thread_func *function, void *aux) 
{
  struct thread *t;
  struct kernel_thread_frame *kf;
  struct switch_entry_frame *ef;
  struct switch_threads_frame *sf;
  struct thread *current_running_thread; 
  
  tid_t tid;

  ASSERT (function != NULL);

  current_running_thread = thread_current ();

  /* Allocate thread. */
  t = palloc_get_page (PAL_ZERO);
  if (t == NULL)
    return TID_ERROR;

  /* Initialize thread. */
  init_thread (t, name, priority);
  tid = t->tid = allocate_tid ();
  t->recent_cpu = 0; 
  
  if (thread_mlfqs)
    thread_calc_prio_mlfqs (t); //recalculate priority

  /* Stack frame for kernel_thread(). */
  kf = alloc_frame (t, sizeof *kf);
  kf->eip = NULL;
  kf->function = function;
  kf->aux = aux;

  /* Stack frame for switch_entry(). */
  ef = alloc_frame (t, sizeof *ef);
  ef->eip = (void (*) (void)) kernel_thread;

  /* Stack frame for switch_threads(). */
  sf = alloc_frame (t, sizeof *sf);
  sf->eip = switch_entry;
  sf->ebp = 0;

#ifdef USERPROG
  t->parent = current_running_thread;
#endif

  /* Add to run queue. */
  thread_unblock (t);
  // number of threads is updated in unblock

  if (thread_get_priority () < t->priority)
    thread_yield ();
  return tid;
}

/* Puts the current thread to sleep.  It will not be scheduled
   again until awoken by thread_unblock().

   This function must be called with interrupts turned off.  It
   is usually a better idea to use one of the synchronization
   primitives in synch.h. */

/* TODO: handle priority_queue */
/* Walter*/
void
thread_block (void) 
{
  ASSERT (!intr_context ()); 
  /*make sure we are not processing any external interrupt*/
  ASSERT (intr_get_level () == INTR_OFF);  

  // list_remove (&thread_current ()->ready_elem);
  thread_current ()->status = THREAD_BLOCKED;
  number_ready_threads--;

  schedule ();
}

/* Transitions a blocked thread T to the ready-to-run state.
   This is an error if T is not blocked.  (Use thread_yield() to
   make the running thread ready.)

   This function does not preempt the running thread.  This can
   be important: if the caller had disabled interrupts itself,
   it may expect that it can atomically unblock a thread and
   update other data. */

bool
thread_unblock (struct thread *t) 
{
  enum intr_level old_level;

  ASSERT (is_thread (t));

  old_level = intr_disable ();
  ASSERT (t->status == THREAD_BLOCKED);
  t->status = THREAD_READY;
  
  priority_q_enqueue (t);

  number_ready_threads++;
  intr_set_level (old_level);
  return t->priority > thread_get_priority ();
}

/* Returns the name of the running thread. */
const char *
thread_name (void) 
{
  return thread_current ()->name;
}

/* Returns the running thread.
   This is running_thread() plus a couple of sanity checks.
   See the big comment at the top of thread.h for details. */
struct thread *
thread_current (void) 
{
  struct thread *t = running_thread ();
  
  /* Make sure T is really a thread.
     If either of these assertions fire, then your thread may
     have overflowed its stack.  Each thread has less than 4 kB
     of stack, so a few big automatic arrays or moderate
     recursion can cause stack overflow. */
  ASSERT (is_thread (t));
  ASSERT (t->status == THREAD_RUNNING);

  return t;
}

/* Returns the running thread's tid. */
tid_t
thread_tid (void) 
{
  return thread_current ()->tid;
}

/* Deschedules the current thread and destroys it.  Never
   returns to the caller. */
/* TODO: handle priority_queue */
/* Akash */
void
thread_exit (void) 
{
  ASSERT (!intr_context ()); 
  /*make sure we are not processing any external interrupt*/

#ifdef USERPROG
  process_exit ();
#endif
  

  /* Remove thread from all threads list, set our status to dying,
     and schedule another process.  That process will destroy us
     when it calls thread_schedule_tail(). */
  intr_disable ();
  list_remove (&thread_current()->allelem);
  thread_current ()->status = THREAD_DYING;
  number_ready_threads--;
  schedule ();
  NOT_REACHED ();
}

/* Yields the CPU.  The current thread is not put to sleep and
   may be scheduled again immediately at the scheduler's whim. */
void
thread_yield (void) 
{
  struct thread *cur = thread_current ();
  enum intr_level old_level;
  
  ASSERT (!intr_context ()); 
  /*make sure we are not processing any external interrupt*/

  old_level = intr_disable ();
  cur->status = THREAD_READY;

  if (cur != idle_thread)
    priority_q_enqueue (cur);
  schedule ();
  intr_set_level (old_level);
}

/* Invoke function 'func' on all threads, passing along 'aux'.
   This function must be called with interrupts off. */
void
thread_foreach (thread_action_func *func, void *aux)
{
  struct list_elem *e;

  ASSERT (intr_get_level () == INTR_OFF);

  for (e = list_begin (&all_list); e != list_end (&all_list);
       e = list_next (e))
    {
      struct thread *t = list_entry (e, struct thread, allelem);
      func (t, aux);
    }
}

/* Sets the current thread's priority to NEW_PRIORITY. */

void
thread_set_priority (int new_priority) 
{
  enum intr_level old_level;

  struct thread *cur = thread_current ();

  old_level = intr_disable ();
  cur->priority = new_priority;
  priority_q.max = MAX(new_priority, priority_q.max);
  
  intr_set_level (old_level);
  thread_yield ();
}

// ================================== TO TEST ==================================
/* move the thread from one ready queue to another */
void
thread_move_in_q (struct thread *t)
{
  ASSERT (intr_get_level () == INTR_OFF);
  ASSERT (t->status == THREAD_READY || t->status == THREAD_BLOCKED);

  if (t->status == THREAD_BLOCKED)
  {
    list_remove (&t->wait_elem);
    thread_unblock (t);
    thread_yield ();
  }
  else
  {
      list_remove (&t->ready_elem);
      priority_q_enqueue (t);
  } 
}
// ================================== TO TEST ==================================

/* Returns the current thread's priority. */
int
thread_get_priority (void) 
{
  struct thread *cur = thread_current ();
  return MAX(cur->priority, cur->donated);
}

int 
thread_get_priority_of (struct thread *t)
{
  return MAX(t->priority, t->donated);
}

/* Updates max_priority on the lock and donated_prio of the holder */
bool
thread_donated (struct thread *t)
{
  int own = thread_get_priority ();
  bool donate = own > thread_get_priority_of (t);

  t->donated = donate ? own : t->donated;
  return donate;
}

/* Updates thread's donated priority by going through all the held locks 
   does not preempt the thread because it still needs to up the sema*/
int 
thread_recalc_donated (struct thread *t)
{
  ASSERT (intr_get_level () == INTR_OFF);
  
  t->donated = 0;
  
  struct list_elem *e;
  for (e = list_begin (&t->locks_held);
       e != list_end (&t->locks_held);
       e = list_next (e))
  {
    struct lock *hl = list_entry (e, struct lock, elem);
    t->donated = MAX(t->donated, hl->max_priority);
  }
  return t->donated;
}

/* Sets the current thread's nice value to NICE. */

void
thread_set_nice (int nice) 
{
  ASSERT (thread_mlfqs);
  enum intr_level old_level;
  old_level = intr_disable ();
  
  struct thread *cur = thread_current ();
  int prio_old = thread_get_priority (); 
  cur->nice = nice;

  thread_calc_prio_mlfqs (cur);
  intr_set_level (old_level);
  
  if (thread_get_priority () <= priority_q.max)
    thread_yield ();
}

/* Returns the current thread's nice value. */
int
thread_get_nice (void) 
{
  return thread_current()->nice;
}


/* Calculationg Priority Function*/
static void
thread_calc_prio_mlfqs (struct thread *t)
{
  fixed_point_t cpu_part, nice_part, x;
  int p_new;

  cpu_part = fp_int_div (t->recent_cpu, 4);
  nice_part = int_to_fp (t->nice * 2);

  x = fp_sub(int_to_fp(PRI_MAX), cpu_part);
  x = fp_sub(x, nice_part);

  p_new = fp_to_int (x);
  p_new = p_new < 0  ? 0  : p_new;
  p_new = p_new > 63 ? 63 : p_new;

  t->priority = p_new;
  // because the thread is running - it doesn't need to move
  // in within the queues
}

/* Returns thead->recent_cpu * 100. */
int
thread_get_recent_cpu (void)
{ 
  fixed_point_t rec_cpu = thread_current ()->recent_cpu;
  rec_cpu = fp_int_mul (rec_cpu, 100);
  return fp_to_int (rec_cpu);
}

int
thread_get_load_avg (void)
{
  return fp_to_int (fp_int_mul (load_avg, 100));
}

/* Idle thread.  Executes when no other thread is ready to run.

   The idle thread is initially put on the ready list by
   thread_start().  It will be scheduled once initially, at which
   point it initializes idle_thread, "up"s the semaphore passed
   to it to enable thread_start() to continue, and immediately
   blocks.  After that, the idle thread never appears in the
   ready list.  It is returned by next_thread_to_run() as a
   special case when the ready list is empty. */
static void
idle (void *idle_started_ ) 
{
  struct semaphore *idle_started = idle_started_;
  idle_thread = thread_current ();
  sema_up (idle_started);

  for (;;) 
    {
      /* Let someone else run. */
      intr_disable ();
      number_ready_threads++; // because it'll get decremented
      thread_block ();

      /* Re-enable interrupts and wait for the next one.

         The `sti' instruction disables interrupts until the
         completion of the next instruction, so these two
         instructions are executed atomically.  This atomicity is
         important; otherwise, an interrupt could be handled
         between re-enabling interrupts and waiting for the next
         one to occur, wasting as much as one clock tick worth of
         time.

         See [IA32-v2a] "HLT", [IA32-v2b] "STI", and [IA32-v3a]
         7.11.1 "HLT Instruction". */
      asm volatile ("sti; hlt" : : : "memory");
    }
}

/* Function used as the basis for a kernel thread. */
static void
kernel_thread (thread_func *function, void *aux) 
{
  ASSERT (function != NULL);

  intr_enable ();       /* The scheduler runs with interrupts off. */
  function (aux);       /* Execute the thread function. */
  thread_exit ();       /* If function() returns, kill the thread. */
}

/* Returns the running thread. */
struct thread *
running_thread (void) 
{
  uint32_t *esp;

  /* Copy the CPU's stack pointer into `esp', and then round that
     down to the start of a page.  Because `struct thread' is
     always at the beginning of a page and the stack pointer is
     somewhere in the middle, this locates the curent thread. */
  asm ("mov %%esp, %0" : "=g" (esp));
  return pg_round_down (esp);
}

/* Returns true if T appears to point to a valid thread. */
static bool
is_thread (struct thread *t)
{
  return t != NULL && t->magic == THREAD_MAGIC;
}

/* Does basic initialization of T as a blocked thread named
   NAME. */

static void
init_thread (struct thread *t, const char *name, int priority)
{
  enum intr_level old_level;

  ASSERT (t != NULL);
  ASSERT (PRI_MIN <= priority && priority <= PRI_MAX);
  ASSERT (name != NULL);

  memset (t, 0, sizeof *t);
  t->status = THREAD_BLOCKED;
  strlcpy (t->name, name, sizeof t->name);
  t->stack = (uint8_t *) t + PGSIZE;
  t->priority = priority;
  t->donated = 0;
  t->magic = THREAD_MAGIC;
  t->recent_cpu = 0; // this is done to initialize the first thread
                     // child threads get parent's recent cpu in thread_create
  t->nice = 0;

  list_init (&t->locks_held);
  list_init(&t->file_list);
  //File descriptors numbered 0 and 1 are reserved for the console. So it will start from 2
  t->fd = 2;

#ifdef USERPROG
  t->proc = NULL;
  t->parent = NULL;
#endif

  old_level = intr_disable ();
  list_push_back (&all_list, &t->allelem);
  // adding it to appropriate ready q later
  intr_set_level (old_level);
}

/* Allocates a SIZE-byte frame at the top of thread T's stack and
   returns a pointer to the frame's base. */
static void *
alloc_frame (struct thread *t, size_t size) 
{
  /* Stack data is always allocated in word-size units. */
  ASSERT (is_thread (t));
  ASSERT (size % sizeof (uint32_t) == 0);

  t->stack -= size;
  return t->stack;
}

/* Chooses and returns the next thread to be scheduled.  Should
   return a thread from the run queue, unless the run queue is
   empty.  (If the running thread can continue running, then it
   will be in the run queue.)  If the run queue is empty, return
   idle_thread. */

static struct thread *
next_thread_to_run (void) 
{
  int next = -1;
  // this part can be definitely improved as we just iterate from
  // the maximal recoreded priority down and look for a non-empty queue
  for (int i=priority_q.max; i>=PRI_MIN; --i)
    if (!list_empty (&priority_q.queue[i]))
      {
        next = i;
        priority_q.max = i;
        break;
      }
  if (next < 0) // all queues empty
    return idle_thread;
  else
    return list_entry (list_pop_front (
      &priority_q.queue[next]), struct thread, ready_elem);
}

/* Completes a thread switch by activating the new thread's page
   tables, and, if the previous thread is dying, destroying it.

   At this function's invocation, we just switched from thread
   PREV, the new thread is already running, and interrupts are
   still disabled.  This function is normally invoked by
   thread_schedule() as its final action before returning, but
   the first time a thread is scheduled it is called by
   switch_entry() (see switch.S).

   It's not safe to call printf() until the thread switch is
   complete.  In practice that means that printf()s should be
   added at the end of the function.

   After this function and its caller returns, the thread switch
   is complete. */

void
thread_schedule_tail (struct thread *prev)
{
  struct thread *cur = running_thread ();
  
  ASSERT (intr_get_level () == INTR_OFF);

  cur->status = THREAD_RUNNING;
  // number_ready_threads--;

  /* Start new time slice. */
  thread_ticks = 0;

#ifdef USERPROG
  /* Activate the new address space. */
  process_activate ();
#endif

  /* If the thread we switched from is dying, destroy its struct
     thread.  This must happen late so that thread_exit() doesn't
     pull out the rug under itself.  (We don't free
     initial_thread because its memory was not obtained via
     palloc().) */
  if (prev != NULL && prev->status == THREAD_DYING && prev != initial_thread) 
    {
      ASSERT (prev != cur);
      palloc_free_page (prev);
    }
}

/* Schedules a new process.  At entry, interrupts must be off and
   the running process's state must have been changed from
   running to some other state.  This function finds another
   thread to run and switches to it.

   It's not safe to call printf() until thread_schedule_tail()
   has completed. */
static void
schedule (void) 
{
  struct thread *cur = running_thread ();
  struct thread *next = next_thread_to_run ();
  struct thread *prev = NULL;

  ASSERT (intr_get_level () == INTR_OFF);
  ASSERT (cur->status != THREAD_RUNNING);
  ASSERT (is_thread (next));
  // nobody should hold the lock when scheduling
  ASSERT (priority_q.q_lock.semaphore.value > 0);

  if (cur != next)
    prev = switch_threads (cur, next);
  // if not updated w other threads - gets updated next time in next_to_run ()
  thread_schedule_tail (prev);
}

/* Returns a tid to use for a new thread. */
static tid_t
allocate_tid (void) 
{
  static tid_t next_tid = 1;
  tid_t tid;

  lock_acquire (&tid_lock);
  tid = next_tid++;
  lock_release (&tid_lock);

  return tid;
}

/* Offset of `stack' member within `struct thread'.
   Used by switch.S, which can't figure it out on its own. */
uint32_t thread_stack_ofs = offsetof (struct thread, stack);

struct thread*
get_t_ready (struct list_elem* thread_pointer)
{
  return list_entry (thread_pointer, struct thread, ready_elem);
}

struct thread*
get_t_waiting (struct list_elem* thread_pointer)
{
  return list_entry (thread_pointer, struct thread, wait_elem);
}

int
num_threads_in_ready_q ()
{
  int num = 0;
  for (int i = 0; i < 64; i++)
    num += list_size (&priority_q.queue[i]);
  return num;
}