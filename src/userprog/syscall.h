#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stdbool.h>
#include <debug.h>

typedef int pid_t;

// create a struct to store the current thread's file descriptors and 
// related information
struct file_entry
{
    struct list_elem file_elem;
    struct file *file_addr;
    int file_descriptor;
};

void syscall_init (void);

void halt (void) NO_RETURN;
void exit (int status) NO_RETURN;
pid_t exec (const char *file);
int wait (pid_t);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned length);
int write (int fd, const void *buffer, unsigned length);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);

/* Ensures that a given pointer is in valid user memory. */
void check_valid_addr (const void *ptr_to_check);

/* Ensures that each memory address in a given buffer is in valid user space. */
void check_buffer (void *buff_to_check, unsigned size);


// check if ptr is a valid page
void * check_valid_page(void *ptr);

// find file entry by its file descriptor
struct file_entry* find_file_entry_by_fd(int fd);

// get arguments from stack
void get_args (struct intr_frame *f, int * args, int argc);

#endif /* userprog/syscall.h */
