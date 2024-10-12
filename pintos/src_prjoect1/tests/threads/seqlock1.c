/* Low priority thread L acquires a lock, then blocks downing a
   semaphore.  Medium priority thread M then blocks waiting on
   the same semaphore.  Next, high priority thread H attempts to
   acquire the lock, donating its priority to L.

   Next, the main thread ups the semaphore, waking up L.  L
   releases the lock, which wakes up H.  H "up"s the semaphore,
   waking up M.  H terminates, then M, then L, and finally the
   main thread.

   Written by Godmar Back <gback@cs.vt.edu>. */

#include <stdio.h>
#include "tests/threads/tests.h"
#include "threads/init.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "devices/timer.h"
#include "threads/malloc.h"

void
test_seqlock1 (void) 
{
  struct seqlock seqlock;
  int64_t sequence;

  /* This test does not work with the MLFQS. */
  ASSERT (!thread_mlfqs);

  /* Make sure our priority is the default. */
  ASSERT (thread_get_priority () == PRI_DEFAULT);

  seqlock_init (&seqlock);
  
  write_seqlock(&seqlock);
  msg ("Thread main acquire write lock.");
  
  sequence = read_seqlock_begin(&seqlock);

  if (sequence % 2 == 0) {
    fail ("sequence is not odd!.");
  }
  
  write_sequnlock(&seqlock);
  msg ("Thread main release write lock.");
}
