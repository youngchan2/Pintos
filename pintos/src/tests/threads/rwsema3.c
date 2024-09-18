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

static thread_func r_thread_func;
static thread_func w_thread_func;

void
test_rwsema3 (void) 
{
  int64_t start_time;
  struct rw_semaphore rwsema;

  /* This test does not work with the MLFQS. */
  ASSERT (!thread_mlfqs);

  /* Make sure our priority is the default. */
  ASSERT (thread_get_priority () == PRI_DEFAULT);

  rwsema_init (&rwsema);
  down_read(&rwsema);
  msg ("Thread main downed read.");
  thread_create ("writer", PRI_DEFAULT, w_thread_func, &rwsema);
  up_read (&rwsema);
  msg ("Thread main up read.");
  start_time = timer_ticks ();
  while (timer_elapsed (start_time) < 10 * TIMER_FREQ)
    continue;
  down_write(&rwsema);
  up_write(&rwsema);
}

static void
w_thread_func (void *ls_) 
{
  int64_t start_time;
  struct rw_semaphore *ls = ls_;

  down_write (ls);
  start_time = timer_ticks ();
  while (timer_elapsed (start_time) < 2 * TIMER_FREQ)
    continue;
  msg ("Thread writer downed write.");
  up_write (ls);
  msg ("Thread writer up write.");
}

static void
r_thread_func (void *ls_) 
{
  int64_t start_time;
  struct rw_semaphore *ls = ls_;

  down_read (ls);
  start_time = timer_ticks ();
  while (timer_elapsed (start_time) < 2 * TIMER_FREQ)
    continue;
  msg ("Thread reader downed read.");
  up_read (ls);
  msg ("Thread reader up read.");
}
