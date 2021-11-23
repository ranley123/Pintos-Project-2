#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "threads/init.h"
#include "devices/shutdown.h" /* Imports shutdown_power_off() for use in halt(). */
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "userprog/process.h"
#include "devices/input.h"
#include "threads/malloc.h"

static void syscall_handler (struct intr_frame *);

// check if ptr is a valid page
void * check_valid_page(void *ptr);

// find file entry by its file descriptor
struct file_entry* find_file_entry_by_fd(int fd);

// get arguments from stack
void get_args (struct intr_frame *f, int * args, int argc);


/* Lock is in charge of ensuring that only one process can access the file system at one time. */
struct lock lock_filesys;

void
syscall_init (void)
{
  /* Initialize the lock for the file system. */
  lock_init(&lock_filesys);

  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

/* Handles a system call initiated by a user program. */
static void
syscall_handler (struct intr_frame *f UNUSED)
{
    /* First ensure that the system call argument is a valid address. If not, exit immediately. */
    check_valid_addr((const void *) f->esp);

    /* Holds the stack arguments that directly follow the system call. */
    int args[3];

    /* Stores the physical page pointer. */
    void * phys_page_ptr;

		/* Get the value of the system call (based on enum) and call corresponding syscall function. */
		switch(*(int *) f->esp)
		{
			case SYS_HALT:
        /* Call the halt() function, which requires no arguments */
				halt();
				break;

			case SYS_EXIT:
        /* Exit has exactly one stack argument, representing the exit status. */
        get_args(f, &args[0], 1);

				/* We pass exit the status code of the process. */
				exit(args[0]);
				break;

			case SYS_EXEC:
				get_args(f, &args[0], 1);

        phys_page_ptr = check_valid_page((void *) args[0]);
        if(phys_page_ptr == NULL){
          exit(-1);
        }

        args[0] = (int) phys_page_ptr;

        lock_acquire(&lock_filesys);
				f->eax = exec((const char *) args[0]);
        lock_release(&lock_filesys);
				break;

			case SYS_WAIT:
        // the first argument is the pid of the child process waited by 
        // the current one
				get_args(f, &args[0], 1);

				f->eax = wait((pid_t) args[0]);
				break;

			case SYS_CREATE:
				get_args(f, &args[0], 2);

        check_buffer((void *)args[0], args[1]);

        phys_page_ptr = check_valid_page((void *) args[0]);
        if(phys_page_ptr == NULL){
          exit(-1);
        }

        args[0] = (int) phys_page_ptr;
        lock_acquire(&lock_filesys);
        f->eax = create((const char *) args[0], (unsigned) args[1]);
        lock_release(&lock_filesys);
				break;

			case SYS_REMOVE:
        get_args(f, &args[0], 1);

        void * phys_page_ptr = check_valid_page((void *) args[0]);
        if(phys_page_ptr == NULL){
          exit(-1);
        }
        args[0] = (int) phys_page_ptr;

        lock_acquire(&lock_filesys);
        f->eax = remove((const char *) args[0]);
        lock_release(&lock_filesys);
				break;

			case SYS_OPEN:
        get_args(f, &args[0], 1);

        phys_page_ptr = check_valid_page((const void *) args[0]);
        if(phys_page_ptr == NULL){
          exit(-1);
        }
        args[0] = (int) phys_page_ptr;

        lock_acquire(&lock_filesys);
        f->eax = open((const char *) args[0]);
        lock_release(&lock_filesys);

				break;

			case SYS_FILESIZE:
        get_args(f, &args[0], 1);

        lock_acquire(&lock_filesys);
        f->eax = filesize(args[0]);
        lock_release(&lock_filesys);
				break;

			case SYS_READ:
        // arguments: fd, buffer, buffer length
        get_args(f, &args[0], 3);
        check_buffer((void *)args[1], args[2]);

        phys_page_ptr = check_valid_page((void *) args[1]);
        if(phys_page_ptr == NULL){
          exit(-1);
        }
        args[1] = (int) phys_page_ptr;

        lock_acquire(&lock_filesys);
        f->eax = read(args[0], (void *) args[1], (unsigned) args[2]);
        lock_release(&lock_filesys);
				break;

			case SYS_WRITE:
        // fd, buffer, buffer length
        get_args(f, &args[0], 3);
        check_buffer((void *)args[1], args[2]);

        phys_page_ptr = check_valid_page((void *) args[1]);
        if(phys_page_ptr == NULL){
          exit(-1);
        }
        args[1] = (int) phys_page_ptr;

        lock_acquire(&lock_filesys);
        f->eax = write(args[0], (const void *) args[1], (unsigned) args[2]);
        lock_release(&lock_filesys);
        break;

			case SYS_SEEK:
        // arguments: fd, position
        get_args(f, &args[0], 2);

        lock_acquire(&lock_filesys);
        seek(args[0], (unsigned) args[1]);
        lock_release(&lock_filesys);
        break;

			case SYS_TELL:
        get_args(f, &args[0], 1);

        lock_acquire(&lock_filesys);
        // return the position of the next byte
        f->eax = tell(args[0]); 
        lock_release(&lock_filesys);
        break;

			case SYS_CLOSE:
        // argument: fd
        get_args(f, &args[0], 1);
        lock_acquire(&lock_filesys);
        close(args[0]);
        lock_release(&lock_filesys);
				break;

			default:
				exit(-1);
				break;
		}
}

// shut down the machine
void halt (void)
{
	shutdown_power_off();
}

// exit the process and print out its exitcode
void exit (int status)
{
	thread_current()->pcb->exitcode = status;
	printf("%s: exit(%d)\n", thread_current()->name, thread_current()->pcb->exitcode);
  thread_exit ();
}

// write LENGTH bytes into BUFFER which is in FD 
int write (int fd, const void *buffer, unsigned length)
{
  // stdout
	if(fd == 1)
	{
		putbuf(buffer, length);
    return length;
	}
  
  if (fd == 0)
  {
    return 0;
  }

  struct file_entry *t = find_file_entry_by_fd(fd);

  return t == NULL? 0: (int) file_write(t->file_addr, buffer, length);
}

// execute with specific filename
pid_t exec (const char * file)
{
	if(!file)
	{
		return -1;
	}

	pid_t child_tid = process_execute(file);
	return child_tid;
}

// wait for PID child process
int wait (pid_t pid)
{
  return process_wait(pid);
}

// create a file with specific size
bool create (const char *file, unsigned initial_size)
{
  bool file_status = filesys_create(file, initial_size);
  return file_status;
}

// remove a file given filename
bool remove (const char *file)
{
  return filesys_remove(file);
}

// open a file given filename
int open (const char *file)
{
  struct file* f = filesys_open(file);
  if(f == NULL)
  {
    return -1;
  }

  // add a file entry to the current thread
  struct file_entry *new_file = malloc(sizeof(struct file_entry));
  new_file->file_addr = f;

  // get the new file's file descriptor
  int fd = thread_current ()->cur_fd;

  // increase the cur_fd for the next file descriptor
  thread_current ()->cur_fd++;
  new_file->file_descriptor = fd;

  // add the current new file entry 
  list_push_front(&thread_current ()->file_descriptors, &new_file->file_elem);
  return fd;
}

// return file size given fd
int filesize (int fd)
{
  struct file_entry *t = find_file_entry_by_fd(fd);
  return t == NULL? -1: (int) file_length(t->file_addr);
}

// read a file given fd with length bytes read
int read (int fd, void *buffer, unsigned length)
{
  // keyboard
  if (fd == 0)
  {
    return (int) input_getc();
  }

  if (fd == 1)
  {
    return 0;
  }

  struct file_entry *t = find_file_entry_by_fd(fd);
  return t == NULL? -1: (int) file_read(t->file_addr, buffer, length);
}


// go to the next byte position of the current fd
void seek (int fd, unsigned position)
{
  struct file_entry *t = find_file_entry_by_fd(fd);
  if(t == NULL){
    return;
  }
  file_seek(t->file_addr, position);
}

// return the next byte position to be read or write
unsigned tell (int fd)
{
  struct file_entry* t = find_file_entry_by_fd(fd);
  unsigned position = (unsigned) file_tell(t->file_addr);

  return t == NULL? -1: position;
}

// close file given fd
void close (int fd)
{

  struct file_entry* t = find_file_entry_by_fd(fd);
  if(t == NULL){
    return;
  }
  file_close(t->file_addr);
  list_remove(&t->file_elem);
}

/* Check to make sure that the given pointer is in user space,
   and is not null. We must exit the program and free its resources should
   any of these conditions be violated. */
void check_valid_addr (const void *ptr_to_check)
{
  /* Terminate the program with an exit status of -1 if we are passed
     an argument that is not in the user address space or is null. Also make
     sure that pointer doesn't go beyond the bounds of virtual address space.  */
  if(!is_user_vaddr(ptr_to_check) || ptr_to_check == NULL || ptr_to_check < (void *) 0x08048000)
	{
    /* Terminate the program and free its resources */
    exit(-1);
	}
}

void * check_valid_page(void *ptr){
  if (ptr == NULL || pagedir_get_page(thread_current()->pagedir, (const void *)ptr) == NULL)
  {
    return NULL;
  }

  return pagedir_get_page(thread_current()->pagedir, ptr);

}

void check_buffer (void *buff_to_check, unsigned size)
{
  unsigned i;
  char *ptr  = (char * )buff_to_check;
  for (i = 0; i < size; i++)
    {
      check_valid_addr((const void *) ptr);
      ptr++;
    }
}

void get_args (struct intr_frame *f, int *args, int argc)
{
  int i;
  int *ptr;
  for (i = 0; i < argc; i++)
    {
      ptr = (int *) f->esp + i + 1;
      check_valid_addr((const void *) ptr);
      args[i] = *ptr;
    }
}

struct file_entry* find_file_entry_by_fd(int fd){
  if(list_empty(&thread_current()->file_descriptors)){
    return NULL;
  }

  struct list_elem* cur = list_front(&thread_current()->file_descriptors);
  while(cur != NULL){
    struct file_entry *t = list_entry (cur, struct file_entry, file_elem);
    if (t->file_descriptor == fd)
    {
      return t;
    }
    cur = cur->next;
  }
  return NULL;
}