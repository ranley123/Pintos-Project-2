#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
struct PCB {
  struct thread* parent_thread;    /* the parent process. */

  bool waiting;             /* indicates whether parent process is waiting on this. */
  bool exited;              /* indicates whether the process is done (exited). */
  int32_t exitcode;         /* the exit code passed from exit(), when exited = true */

  /* Synchronization */
  struct semaphore sema_wait;             /* the semaphore used for wait() : parent blocks until child exits */
};



tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

#endif /* userprog/process.h */
