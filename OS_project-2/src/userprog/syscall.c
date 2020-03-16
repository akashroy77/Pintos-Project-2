#include "userprog/syscall.h"
#include <stdio.h>
#include <stdbool.h>
#include <syscall-nr.h>
#include <string.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include "devices/shutdown.h"
#include "userprog/pagedir.h"
#include "threads/vaddr.h"
#include "filesys/filesys.h"
#include "filesys/file.h"

//The syscall function that the user program calls takes anywhere between 1 and 3 parameters
#define MAXARGS 3
//The code segment in Pintos starts at user virtual address 0x08048000
#define STARTADDR 0x08048000
//it is not safe to call into the file system code from multiple threads at once. System calls must treat the file system as a critical section
struct lock file_lock;

static void syscall_handler (struct intr_frame *);
tid_t handle_exec (const char *file);
int handle_wait (pid_t pid);
bool handle_filecreate(int *args);
bool handle_fileremove(int *args);
int handle_fileopen(int *args);
void handle_fileclose(int *args);
void handle_seek(int *args);
unsigned handle_tell(int *args);
int handle_fileSize(int *args);
int handle_write(int *args);
int handle_read(int *args);
int handle_write(int *args);
bool is_valid_address (const void *address);
void parse_stack_arguments (struct intr_frame *f, int *args, int size);
bool is_file_open(const void *file_name);
bool is_valid_buffer_space (void* givenBuffer, unsigned size);


void
syscall_init (void) 
{
  lock_init(&file_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

bool
is_valid_address (const void *address)
{
  uint32_t pd = thread_current ()->pagedir;

  return address != NULL &&\
         is_user_vaddr (address + 4) &&\
         address > STARTADDR &&\
         pagedir_get_page (thread_current ()->pagedir, address+3) != NULL &&\
         pagedir_get_page (thread_current ()->pagedir, address) != NULL;
         // TODO: make more efficient (only check if pagedir bits are on)
}

bool is_file_open(const void *file_name)
{
  return (strcmp(file_name, thread_current()->name) == 0);
}
bool
is_valid_buffer_space (void* givenBuffer, unsigned size)
{
  char* buffer;
  for (buffer = (char *) givenBuffer;
       buffer < (char *) (givenBuffer + size);
       buffer++)
    if (!is_valid_address ( (const void*) buffer))
      return false;
  return true;
}

void exit_on_invalid_addr (const void * vaddr)
{
  if (!is_valid_address (vaddr))
    handle_exit (-1);
}

void 
parse_stack_arguments (struct intr_frame *f, int *args, int size)
{
  int count;
  int *stack_traverse;
  for (count = 0; count < size; count++)
    {
    stack_traverse = (int *) f->esp + count + 1;
    if(is_valid_address((const void*) stack_traverse))
      args[count] = *stack_traverse;
    else
      break;
    }
}
struct file* fetch_file(int args)
{
  struct list_elem *e;

      for (e = list_begin (&thread_current()->file_list); e != list_end (&thread_current()->file_list);
           e = list_next (e))
        {
          struct current_file *f = list_entry (e, struct current_file, elem);
          if(f->fd == args)
            return f->file_ptr;
        }
   return NULL;
}

static void
syscall_handler (struct intr_frame *f) 
{
  if (!is_valid_address((const void*) f->esp))
    handle_exit(-1);

  int syscall_code;
  syscall_code = *(int*)f->esp;
  void *next_arg = f->esp + sizeof(int);
  
  int args[MAXARGS];
  int exit_code;
  char *file;
  pid_t pid;

  // printf("In syscall_handler with code: %d\n", syscall_code);

  switch (syscall_code)
  {
    case SYS_HALT:
      shutdown_power_off();
      break;
    case SYS_EXIT:
      exit_on_invalid_addr ((const void *) next_arg);
      handle_exit (*(int*) next_arg);
      break;
    case SYS_EXEC:
      exit_on_invalid_addr ((const void *) next_arg);
      file = *(char**) next_arg;
      exit_on_invalid_addr ((const void *) file);
      f->eax = (int) handle_exec (file);
      break;
    case SYS_WAIT:
      exit_on_invalid_addr ((const void*) next_arg);
      pid = *(pid_t*) next_arg;
      f->eax = handle_wait (pid);
      break;
    case SYS_CREATE:
      parse_stack_arguments (f,&args[0],MAXARGS);
      if(is_valid_buffer_space((void *) args[0], (unsigned) args[1]))
        f->eax=handle_filecreate(args);
      else
        handle_exit(-1);
      break;
    case SYS_REMOVE:
      parse_stack_arguments (f,&args[0],MAXARGS);
      f->eax=handle_fileremove(args);
      break;
    case SYS_OPEN:
      parse_stack_arguments (f,&args[0],MAXARGS);
      exit_on_invalid_addr (args[0]);
      f->eax=handle_fileopen(args);
      break;
    case SYS_CLOSE:
      parse_stack_arguments (f,&args[0],MAXARGS);
      handle_fileclose(args);
      break;
    case SYS_SEEK:
      parse_stack_arguments(f, &args[0], MAXARGS);
      lock_acquire(&file_lock);
      handle_seek(args);
      lock_release(&file_lock);
      break;
    case SYS_FILESIZE:
      parse_stack_arguments(f,&args[0], MAXARGS);
      lock_acquire(&file_lock);
      f->eax = handle_fileSize(args); 
      lock_release(&file_lock);
      break;
    case SYS_TELL:
      parse_stack_arguments(f,&args[0],MAXARGS);
      lock_acquire(&file_lock);
      f->eax = handle_tell(args);
      lock_release(&file_lock);
      break;
    case SYS_READ:
      parse_stack_arguments(f,&args[0],MAXARGS);
      is_valid_buffer_space ((void *) args[1], (unsigned) args[2]);
      if (!is_user_vaddr((const void*)args[1]))
      {
        handle_exit(-1);
      }
      f->eax = handle_read(args);
      break;
    case SYS_WRITE:
      parse_stack_arguments (f,&args[0],MAXARGS);
      if (
        is_valid_address ((const void *) args[1]) &&\
        is_valid_buffer_space ((void *) args[1], (unsigned) args[2])
      )
        f->eax = handle_write(args);
      else
        handle_exit(-1);
      break;
    default: 
      printf("Unrecognised system call: %d\n", syscall_code);
      thread_exit ();
      break;
  }
}

void 
handle_exit (int code)
{ 
  /* setting return value*/
  struct thread *t = thread_current ();
  t->proc->child_rec->exit_value = code;
  // printf("%s exits with code: %d\n", t->name, code);
  printf("%s: exit(%d)\n",t->name, code);
  thread_exit ();
}



pid_t
handle_exec (const char *file)
{
  tid_t tid;
  tid = process_execute (file);
  if (thread_current ()->proc->child_launched)
    return tid*2;
  return TID_ERROR;
}

int
handle_wait (pid_t pid)
{
  if (pid % 2 != 0)
    return -1;
  else
    return process_wait (pid / 2);
}

bool handle_filecreate(int *args)
{
    void *page_ptr = pagedir_get_page(thread_current()->pagedir, (const void *)args[0]);
    if (page_ptr==NULL)
      {
        handle_exit(-1);
      }
    args[0]=(int)page_ptr;
    lock_acquire(&file_lock);
    bool message=filesys_create((const char *)args[0],(unsigned)args[1]);
    lock_release(&file_lock);
    return message;
}

bool handle_fileremove(int *args)
{
    void *page_ptr = pagedir_get_page(thread_current()->pagedir, (const void *)args[0]);
    if (page_ptr==NULL)
      {
        handle_exit(-1);
      }
    args[0]=(int)page_ptr;
    lock_acquire(&file_lock);
    bool message=filesys_remove((const char *)args[0]);
    lock_release(&file_lock);
    return message;
}

int handle_fileopen(int *args)
{
    void *page_ptr = pagedir_get_page(thread_current()->pagedir, (const void *)args[0]);
    if (page_ptr==NULL)
        handle_exit (-1);
    args[0]=(int)page_ptr;

    lock_acquire(&file_lock);
    struct file_ptr* cur_file= filesys_open((const char *)args[0]);
    if (is_file_open((const char *)args[0]))
      file_deny_write(cur_file);
    if(cur_file == NULL)
    {
      lock_release(&file_lock);
      return -1; //No such file in the system
    }
    struct current_file *open_file = malloc(sizeof(struct current_file));
    open_file->file_ptr = cur_file;
    open_file->fd = thread_current()->fd;
    thread_current ()->fd++;
    list_push_back (&thread_current()->file_list, &open_file->elem);
    lock_release(&file_lock);
    return open_file->fd;
}
void handle_fileclose(int *args)
{
  struct current_file *f;
  struct list_elem *e;
  for (e = list_begin ( &thread_current()->file_list);
       e != list_end (&thread_current()->file_list);
           e = list_next (e))
           {
             f = list_entry(e, struct current_file, elem);
             if( args[0] == f->fd)
             {
               file_close (f->file_ptr);
               list_remove (&f->elem);
               free (f);
               return 0;
             }
           }
  return -1; // file not open 
}

void handle_seek(int *args)
{
  struct file * f = fetch_file(args[0]);
      if(!f)
          return;
        file_seek(f, (unsigned) args[1]);
}

unsigned handle_tell(int *args)
{
  struct file *f = fetch_file(args[0]);
  if (!f)
      return -1;
  return file_tell(f);
}

int handle_fileSize(int *args)
{
  
  struct file *f = fetch_file(args[0]);
  if(!f)
    return -1;  
  return file_length(f); 
}


int handle_read(int *args)
{
  void *page_ptr = pagedir_get_page(thread_current()->pagedir, (const void *)args[1]);
  if (!page_ptr)
    {
      handle_exit(-1);
    }
  args[1]=(int)page_ptr;

  if ((int)args[0] == 0)
  {
    uint8_t* buffer = (uint8_t *) args[1];
    int i;
    for (i = 0; i <args[2]; ++i)
      buffer[i] = input_getc();
    return args[2];
  }
  else
  {
    struct file *f = fetch_file (args[0]);
    if (!f)
        return -1;
    else
    {
      lock_acquire (&file_lock);
      int size = file_read (f, (void *) args[1], (unsigned) args[2]);
      lock_release (&file_lock);
      return size;
    }
  }
}

int handle_write(int *args)
{
    void *page_ptr = pagedir_get_page(thread_current()->pagedir, (const void *)args[1]);
    int written_bytes=0;
    lock_acquire(&file_lock);
      if (page_ptr==NULL)
      {
        handle_exit(-1);
      }
      args[1]=(int)page_ptr;
      int fd=args[0];
      struct file *received_file = fetch_file(fd);
      //fd 1 (STDOUT_FILENO) is standard output.
      if(fd==STDOUT_FILENO)
      {
          putbuf((void *)args[1], (unsigned)args[2]);
          lock_release(&file_lock);
          return (int)args[2];
      }
      else if(received_file==NULL)
      {
         lock_release(&file_lock);
         return -1;
      }
      else
      {
        written_bytes= file_write(received_file, (const void *)args[1],(unsigned)args[2]);
        lock_release(&file_lock);
        return written_bytes;
      }     
}
