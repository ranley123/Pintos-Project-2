#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stdbool.h>
#include <debug.h>

typedef int pid_t;

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

// check address
void check_valid_addr (const void *ptr_to_check);

// check buffer is valid in memory
void check_buffer (void *buff_to_check, unsigned size);

// check if ptr is a valid page
void * check_valid_page(void *ptr);

// find file entry by its file descriptor
struct file_entry* find_file_entry_by_fd(int fd);


#endif /* userprog/syscall.h */
