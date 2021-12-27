
# makefile seems to be processed a few times after make clean, and $src isn't always set
# if src isn't set, cd src will go to ~/ and git rev-parse will fail
ifdef src
  BUILD_VERSION := $(shell bash -c 'cd $(src); echo `date +%Y%m%d_%H%M_``git rev-parse --short HEAD`')
  $(info version ${BUILD_VERSION})
endif 

# 1/7/2021 do some feature tests because the block device interface changed in kernel 5.8
HAVE_COMBINED_BLK_ALLOC_QUEUE := $(shell /bin/bash -c 'grep "blk_alloc_queue.*make_request_fn" /usr/src/linux-headers-`uname -r`/include/linux/blkdev.h > /dev/null; echo $$(( 1 - $$? ))')
$(info HAVE_COMBINED_BLK_ALLOC_QUEUE = ${HAVE_COMBINED_BLK_ALLOC_QUEUE})
# 1/8/2021 and for 5.10
HAVE_BLK_ALLOC_QUEUE_NODE := $(shell /bin/bash -c 'grep "blk_alloc_queue.*(int node_id)" /usr/src/linux-headers-`uname -r`/include/linux/blkdev.h > /dev/null; echo $$(( 1 - $$? ))')
$(info HAVE_BLK_ALLOC_QUEUE_NODE = ${HAVE_BLK_ALLOC_QUEUE_NODE})

HAVE_BIO_START_IO_ACCT := $(shell /bin/bash -c 'grep "bio_start_io_acct.*struct bio"    /usr/src/linux-headers-`uname -r`/include/linux/blkdev.h > /dev/null; echo $$(( 1 - $$? ))')
$(info HAVE_BIO_START_IO_ACCT = ${HAVE_BIO_START_IO_ACCT})

# 12/24/2021 they got rid of hd_struct somewhere around 5.11
HAVE_HD_STRUCT                 := $(shell /bin/bash -c 'grep "struct hd_struct"      /usr/src/linux-headers-`uname -r`/include/linux/genhd.h > /dev/null; echo $$(( 1 - $$? ))')
$(info HAVE_HD_STRUCT = ${HAVE_HD_STRUCT})

obj-m += dblock.o
dblock-y := dblocktools.o dblockmain.o

# if you're debugging the kernel, helps to turn optimizations off MY_CFLAGS += -g -DDEBUG -O0
#MY_CFLAGS += -g -DDEBUG -Wunused-result
MY_CFLAGS += -Wunused-result
MY_CFLAGS += -DHAVE_COMBINED_BLK_ALLOC_QUEUE=${HAVE_COMBINED_BLK_ALLOC_QUEUE}
MY_CFLAGS += -DHAVE_BIO_START_IO_ACCT=${HAVE_BIO_START_IO_ACCT}
MY_CFLAGS += -DHAVE_BLK_ALLOC_QUEUE_NODE=${HAVE_BLK_ALLOC_QUEUE_NODE}
MY_CFLAGS += -DHAVE_HD_STRUCT=${HAVE_HD_STRUCT}
ccflags-y += ${MY_CFLAGS}
ccflags-y += -DBUILD_VERSION=\"$(BUILD_VERSION)\"

CC += ${MY_CFLAGS}


all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules EXTRA_CFLAGS="${MY_CFLAGS}"

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

