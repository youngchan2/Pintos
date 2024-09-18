#ifndef THREADS_SYNCH_H
#define THREADS_SYNCH_H

#include <list.h>
#include <stdbool.h>

/* A counting semaphore. */
struct semaphore
{
  unsigned value;      /* Current value. */
  struct list waiters; /* List of waiting threads. */
};

void sema_init(struct semaphore *, unsigned value);
void sema_down(struct semaphore *);
bool sema_try_down(struct semaphore *);
void sema_up(struct semaphore *);
void sema_self_test(void);

/* Lock. */
struct lock
{
  struct thread *holder;      /* Thread holding lock (for debugging). */
  struct semaphore semaphore; /* Binary semaphore controlling access. */
};

void lock_init(struct lock *);
void lock_acquire(struct lock *);
bool lock_try_acquire(struct lock *);
void lock_release(struct lock *);
bool lock_held_by_current_thread(const struct lock *);

/* Condition variable. */
struct condition
{
  struct list waiters; /* List of waiting threads. */
};

void cond_init(struct condition *);
void cond_wait(struct condition *, struct lock *);
void cond_signal(struct condition *, struct lock *);
void cond_broadcast(struct condition *, struct lock *);

struct rw_semaphore
{
  unsigned rcount;
  struct list read_waiters;
  struct list write_waiters;
  struct thread *writer;
};

void rwsema_init(struct rw_semaphore *);
void down_write(struct rw_semaphore *);
void down_read(struct rw_semaphore *);
void up_write(struct rw_semaphore *);
void up_read(struct rw_semaphore *);

struct seqlock
{
  int64_t sequence;
  struct thread *writer;
};
void seqlock_init(struct seqlock *);
int64_t read_seqlock_begin(struct seqlock *);
bool read_seqretry(struct seqlock *, int64_t);
void write_seqlock(struct seqlock *);
void write_sequnlock(struct seqlock *);

/* Optimization barrier.

   The compiler will not reorder operations across an
   optimization barrier.  See "Optimization Barriers" in the
   reference guide for more information.*/
#define barrier() asm volatile("" : : : "memory")
#endif /* threads/synch.h */
