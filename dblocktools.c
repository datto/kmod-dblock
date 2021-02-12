
// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2020-2021 Datto Inc.
 */
#include <linux/sched.h>
#include "dblocktools.h"

#define FALSE 0
#define TRUE 1

int dblock_errno = 0;

int SET_ERROR(int er)
  {
    dblock_errno = er;
    return er;
  }

void pil_mutex_init(pil_mutex_t *lock)
  {
    mutex_init(&lock->m);
  }

void pil_mutex_lock(pil_mutex_t *lock)
  {
    mutex_lock(&lock->m);
  }

void pil_mutex_unlock(pil_mutex_t *lock)
  {
    mutex_unlock(&lock->m);
  }

void pil_cv_init(pil_cv_t *cv){
    init_waitqueue_head(&cv->cv_wq);
}

void pil_cv_signal(pil_cv_t *cv){
    wake_up_interruptible(&cv->cv_wq);
}

void pil_cv_broadcast(pil_cv_t *cv){
    wake_up_interruptible_all(&cv->cv_wq);
}

static void pil_cv_wait_impl(pil_cv_t *cv, pil_mutex_t *lock, boolean_t io_wait){
    DEFINE_WAIT(wait);

    prepare_to_wait_exclusive(&cv->cv_wq, &wait, TASK_INTERRUPTIBLE);
    pil_mutex_unlock(lock);

    if (io_wait) io_schedule();
    else schedule();

    finish_wait(&cv->cv_wq, &wait);
    pil_mutex_lock(lock);
}

void pil_cv_wait(pil_cv_t *cv, pil_mutex_t *lock){
    pil_cv_wait_impl(cv, lock, FALSE);
}

void pil_cv_wait_io(pil_cv_t *cv, pil_mutex_t *lock){
    pil_cv_wait_impl(cv, lock, TRUE);
}

int pil_cv_timedwait(pil_cv_t *cv, pil_mutex_t *lock, u64 msec){
    u64 jiffies_left;
    u64 msechz;
    DEFINE_WAIT(wait);

    prepare_to_wait_exclusive(&cv->cv_wq, &wait, TASK_INTERRUPTIBLE);
    pil_mutex_unlock(lock);

    msechz = msec;
    do_div(msechz, MSEC_PER_SEC);
    msechz *= HZ;
    jiffies_left = schedule_timeout(msechz);

    finish_wait(&cv->cv_wq, &wait);
    pil_mutex_lock(lock);

    return (jiffies_left > 0) ? 0 : SET_ERROR(ETIMEDOUT);
}

void pil_cv_destroy(pil_cv_t *cv){
}
