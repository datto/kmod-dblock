
// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2020-2021 Datto Inc.
 */
#pragma once

#include <linux/sched.h>
#include <linux/wait.h>

typedef struct
 {
    wait_queue_head_t cv_wq;
 } pil_cv_t;

typedef struct
  {
    struct mutex m;
  } pil_mutex_t;

typedef int boolean_t;

typedef void pil_lockref_t;

void pil_mutex_init(pil_mutex_t *lock);
void pil_mutex_lock(pil_mutex_t *lock);
void pil_mutex_unlock(pil_mutex_t *lock);
void pil_cv_init(pil_cv_t *cv);
void pil_cv_signal(pil_cv_t *cv);
void pil_cv_broadcast(pil_cv_t *cv);
void pil_cv_wait(pil_cv_t *cv, pil_mutex_t *lock);
void pil_cv_wait_io(pil_cv_t *cv, pil_mutex_t *lock);
int pil_cv_timedwait(pil_cv_t *cv, pil_mutex_t *lock, u64 msec);
void pil_cv_destroy(pil_cv_t *cv);
