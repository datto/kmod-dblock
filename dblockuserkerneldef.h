
// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2020-2021 Datto Inc.
 */
#pragma once

#ifndef __KERNEL__

  typedef signed char s8;
  typedef unsigned char u8;

  typedef signed short s16;
  typedef unsigned short u16;

  typedef signed int s32;
  typedef signed int i32;
  typedef unsigned int u32;

  typedef signed long long s64;
  typedef signed long long i64;
  typedef unsigned long long u64;

  #define PAGE_SIZE 4096

  #define DISK_NAME_LEN 32

#else

  #include <linux/genhd.h>

#endif

