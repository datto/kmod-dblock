
// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2020-2021 Datto Inc.
 */
#include <linux/miscdevice.h>
#include <linux/types.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/crc32.h>
#include <linux/init.h>
#include <linux/wait.h>
#include <linux/gfp.h>
#include <linux/hdreg.h>
#include <linux/blkdev.h>
#include <linux/sched/signal.h>
#include <linux/delay.h>
#include <linux/ctype.h>
#include <linux/version.h>

#include <linux/kern_levels.h>
#include <linux/moduleparam.h>
#include <linux/stat.h>
#include <linux/blk_types.h>
#include <linux/genhd.h>

#include "dblocktools.h"
#include "dblock.h"

#define DBLOCK_VERSION  BUILD_VERSION

#define DBLOCK_LICENSE  "GPL"

#define DBLOCK_AUTHOR   "Stu Mark <smark@datto.com>"
#define DBLOCK_DESC     "kernel driver for dblock object store block device"

#define DBLOCK_CONTROL_DEVICE_NAME "dblockctl"

#define KERNEL_SECTOR_SIZE 512

#define STATE_RUNNING 0
#define STATE_SHUTDOWN 1
#define STATE_FORCE_SHUTDOWN 2

static int max_minors = 255;

static int debug_logs = 0;

static int data_interrogation = 0;

#define log_kern_debug(fmt, args...)  do{ if(debug_logs) printk(KERN_DEBUG "dblock:[%d] debug kernel:    " fmt "\n", current->pid, ## args); }while(0)
#define log_kern_info(fmt, args...)                      printk(KERN_INFO  "dblock:[%d] info  kernel:    " fmt "\n", current->pid, ## args)
#define log_kern_error(error, fmt, args...)              printk(KERN_ERR   "dblock:[%d] error kernel:    " fmt ": error %d\n", current->pid, ## args, error)

#define log_user_debug(fmt, args...)  do{ if(debug_logs) printk(KERN_DEBUG "dblock:[%d] debug userspace: " fmt "\n", current->pid, ## args); }while(0)
#define log_user_info(fmt, args...)                      printk(KERN_INFO  "dblock:[%d] info  userspace: " fmt "\n", current->pid, ## args)
#define log_user_error(error, fmt, args...)              printk(KERN_ERR   "dblock:[%d] error userspace: " fmt ": %d\n", current->pid, ## args, error)

void hexdump(void *ptr, int buflen)
{
    unsigned char *buf = (unsigned char*) ptr;
    int i, j;
    for (i = 0; i < buflen; i += 16) {
        for (j = 0; j < 16; j++)
            if (i + j < buflen)
                printk("%02x ", buf[i + j]);
            else
                printk("   ");
        printk(" ");
        for (j = 0; j < 16; j++)
            if (i + j < buflen)
                printk("%c", isprint(buf[i + j]) ? buf[i + j] : '.');
        printk("\n");
    }
}

void hexdumpbuf(char *out , void *ptr)
{
    int buflen = 16;
    unsigned char *buf = (unsigned char *) ptr;
    int i, j;
    char *pos = out;
    memset(out, 0xff, 119);

    for (i = 0; i < buflen; i += 16) {
        for (j = 0; j < 16; j++)
            if (i + j < buflen)
                pos += sprintf(pos, "%02x ", buf[i + j]);
            else
                pos += sprintf(pos, "   ");
        pos += sprintf(pos, " ");
        for (j = 0; j < 16; j++)
            if (i + j < buflen)
                pos += sprintf(pos, "%c", isprint(buf[i + j]) ? buf[i + j] : '.');
    }
}

u64 hashup (char *start, u64 length)
  {
    if (debug_logs)
      return crc32(0x80000000, start, length);
    else
      return 0;
  }

module_param(max_minors, int, 0000);
MODULE_PARM_DESC(max_minors, "the maximum number of concurrent dblock devices the kernel module will support");

module_param(debug_logs, int, S_IRUSR | S_IWUSR);
MODULE_PARM_DESC(debug_logs, "whether to show debug logs or not");

module_param(data_interrogation, int, S_IRUSR | S_IWUSR);
MODULE_PARM_DESC(data_interrogation, "whether to show data interrogation");

static struct master_control_state_t
  {
    pil_mutex_t control_lock_mutex;
    u32 next_device_handle;

    struct list_head active_device_list;

  } master_control_state;

typedef struct device_state_t {
    pil_mutex_t device_state_lock_mutex;
    atomic_t in_use;
    char *device_name;
    u32 block_device_registered;
    int major;
    int dev_open_count;
    struct request_queue *queue;
    struct gendisk *gendisk;
    char *io_dev_name;
    struct miscdevice io_dev;
    u64 size;
    u32 kernel_block_size;
    u64 number_of_blocks;
    u32 max_segments_per_request;
    u32 timeout_milliseconds;
    atomic_t shutting_down;
    u32 handle_id;

    pil_mutex_t request_block_lock;
    pil_cv_t request_block_cv;

    u32 concurrent_list_unprocessed_count;

    u32 next_operation_id;

    struct list_head concurrent_operations_list;

    struct list_head list_anchor;
} device_state;

static int device_getgeo(struct block_device * block_device, struct hd_geometry * geo);
static int device_open(struct block_device *blk_dev, fmode_t mode);
static void device_release(struct gendisk *gd, fmode_t mode);
static long device_ioctl(struct file *f, unsigned int cmd, unsigned long __user userspace);
static s32 create_concurrent_operation_entry(device_state *device, dblock_context **context);
static void delete_concurrent_operation_entry(device_state *device, dblock_context *context);
static s32 find_device_by_handle_id(u32 handle_id, device_state **deviceout);
static void block_device_cleanup(device_state *ending_device);
static void disk_stats_start(struct request_queue *q, struct bio *bio, struct gendisk *gd);
static void disk_stats_end(struct request_queue *q, struct bio *bio, struct gendisk *gd, unsigned long start_time);
#if HAVE_BLK_ALLOC_QUEUE_NODE == 1
static blk_qc_t bio_request_handler(struct bio *bio);
#endif

static void device_get(device_state *device)
  {
    atomic_inc(&device->in_use);
  }

static void device_put(device_state *device)
  {

    if (device == NULL)
      {
        log_kern_error(-EINVAL, "sanity failure, somebody called device_put with a NULL device.");
        return;
      }

    if (atomic_dec_and_test(&device->in_use))
      {
        log_kern_debug("last reference count to device_id %d, calling block_device_cleanup", device->handle_id);
        log_kern_info("removing block device");

        block_device_cleanup(device);
      }
  }

struct block_device_operations dblock_blk_dev_ops = {
    .owner         = THIS_MODULE,
    .open          = device_open,
#if HAVE_BLK_ALLOC_QUEUE_NODE == 1
    .submit_bio    = bio_request_handler,
#endif
    .release       = device_release,
    .getgeo        = device_getgeo,
};

static void find_unprocessed_item(device_state *device, dblock_context **something_to_do_context)
  {
    dblock_context *search_context = NULL;
    *something_to_do_context = NULL;
    log_user_debug("looking through concurrent operations list for unprocessed items.");

    list_for_each_entry(search_context, &device->concurrent_operations_list, list_anchor)
      {
        if (search_context->processed != 0)
          log_user_debug("operation_id %u already processed", search_context->op.operation_id);
        else
          {
            log_user_debug("operation_id %u has not been processed yet, going to do that one", search_context->op.operation_id);
            *something_to_do_context = search_context;

            (*something_to_do_context)->processed = 1;

            device->concurrent_list_unprocessed_count--;
            log_user_debug("decrementing unprocessed count to %u", device->concurrent_list_unprocessed_count);
            log_user_debug("locking response lock for operation_id %u", (*something_to_do_context)->op.operation_id);
            pil_mutex_lock(&((*something_to_do_context)->response_lock));
            break;
          }
      }
  }

static s32 handle_kernel_request_special(device_state *device, unsigned long __user userspace, dblock_context *context_ptr)
  {
    unsigned long copyret;
    u32 copyamount;
    u32 count;
    u32 ret;
    dblock_operation *userspaceop = (dblock_operation *)userspace;
    dblock_operation_state *bio_segment;
    copyamount = 0;
    copyret = 0;
    ret = 0;

    if (debug_logs)
      {
        dblock_context *count_ptr = NULL;
        u32 unprocessed = 0;
        count = 0;
        list_for_each_entry(count_ptr, &device->concurrent_operations_list, list_anchor)
          {
            count++;
            if (count_ptr->processed == 0)
              unprocessed++;
          }
        log_user_debug("Number of items in concurrent operations list: %u, unprocessed %u", count, unprocessed);
      }

    log_user_debug("operation block for request found item on head of list operation_id: %u, cmd: %u ", context_ptr->op.operation_id, context_ptr->op.header.operation);

    count = 0;
    bio_segment = NULL;
    list_for_each_entry(bio_segment, &context_ptr->bio_segments_op_state_list, list_anchor)
      {
        dblock_bio_segment_metadata *entry;
        log_user_debug("copying metadata for bio_segment %lld to dblock_operation, start %lld, length %lld", bio_segment->id, bio_segment->request_start, bio_segment->request_length);
        entry = &(context_ptr->op.metadata[count]);
        count++;
        if (count > context_ptr->number_of_segments_in_list)
          {

            log_user_error(-EOVERFLOW, "kernel side sent userspace more bio segments than we can handle %d/%d. Sanity failure.", count, context_ptr->number_of_segments_in_list);
            ret = -EOVERFLOW;
            goto error;
          }
        entry->start = bio_segment->request_start;
        entry->length = bio_segment->request_length;
      }

    if (data_interrogation)
      {
        log_user_debug("copying request to userspace dblock->op before returning, copy from %p to %p", &context_ptr->op, userspaceop);
      }
    copyamount = sizeof(dblock_operation);

    copyret = copy_to_user(userspaceop, &context_ptr->op, copyamount);

    if (copyret != 0)
      {
        log_user_error(-EINVAL, "Unable to copy kernel block thread request to userspace, failed to copy %ld bytes", copyret);
        ret = -EINVAL;
        goto error;
      }

    if (context_ptr->op.header.operation == DEVICE_OPERATION_KERNEL_WRITE_REQUEST)
      {
        char *bio_segment_buffer;
        char *page_buffer;
        char *userspacedatabufferpos;
        u32 pointerpositioncounter;

        pointerpositioncounter = 0;
        userspacedatabufferpos = userspaceop->userspacedatabuffer;

        count = 0;
        bio_segment = NULL;
        list_for_each_entry(bio_segment, &context_ptr->bio_segments_op_state_list, list_anchor)
          {
            dblock_bio_segment_metadata *entry;
            log_user_debug("copying write data for bio_segment %lld to dblock_operation userspacedatabuffer.", bio_segment->id);
            entry = &(context_ptr->op.metadata[count]);
            count++;
            if (count > context_ptr->number_of_segments_in_list)
              {
                log_user_error(-EOVERFLOW, "kernel side sent userspace more bio segments than we can handle %d/%d. Sanity failure.", count, context_ptr->number_of_segments_in_list);
                ret = -EOVERFLOW;
                goto error;
              }

            if (pointerpositioncounter + entry->length > MAX_BIO_SEGMENTS_BUFFER_SIZE_PER_REQUEST)
              {
                log_user_error(-EOVERFLOW, "kernel side sent userspace more bio segment DATA than we can fit in the userspace data buffer %lld/%d. Sanity failure.",
                               pointerpositioncounter + entry->length, MAX_BIO_SEGMENTS_BUFFER_SIZE_PER_REQUEST);
                ret = -EOVERFLOW;
                goto error;
              }

            page_buffer = kmap(bio_segment->bv_page);
            bio_segment_buffer = page_buffer + bio_segment->offset;
            if (data_interrogation)
              {
                log_user_debug("copy databuffer from %p to %p", bio_segment_buffer, userspacedatabufferpos);
              }

            copyret = copy_to_user(userspacedatabufferpos, bio_segment_buffer, entry->length);
            kunmap(bio_segment->bv_page);

            if (copyret != 0)
              {
                log_user_error(EINVAL, "Unable to copy kernel block thread data to userspace, failed to copy %ld bytes", copyret);
                ret = -ENOMEM;
                goto error;
              }
            log_user_debug("Copied %lld bytes for write to userspace directly from kernel buffer %p to %p", entry->length,
                           bio_segment_buffer, userspacedatabufferpos);
            userspacedatabufferpos += entry->length;
            pointerpositioncounter += entry->length;
          }
      }

    error:
    return ret;
  }

static void make_operation_return_signal(device_state *device, int signal_number, unsigned long __user userspace)
  {
    u32 copyamount;
    dblock_operation *userspaceop = (dblock_operation *)userspace;

    dblock_operation *dummy = NULL;
    u32 op_id;
    unsigned long copyret;
    s32 ret = 0;

    dummy = kmalloc(sizeof(dblock_operation), GFP_KERNEL);
    if (dummy == NULL)
      {
        log_kern_error(ENOMEM, "Unable to allocate memory for dummy userspace response in make_operation_return_signal.");
        log_kern_error(ENOMEM, "userspace is going to get an undefined response from us, good luck, godspeed.");
        ret = -ENOMEM;
        goto error;
      }

    memset(dummy, 0, sizeof(dblock_operation));

    pil_mutex_lock(&device->device_state_lock_mutex);
    op_id = ++device->next_operation_id;
    dummy->operation_id = op_id;
    pil_mutex_unlock(&device->device_state_lock_mutex);
    log_user_debug("New operation_id for dummy: %u", dummy->operation_id);
    dummy->header.operation = DEVICE_OPERATION_KERNEL_BLOCK_FOR_REQUEST;
    dummy->header.size = 0;
    dummy->header.signal_number = signal_number;

    copyamount = 0;
    copyret = 0;

    copyamount = sizeof(dblock_operation);

    log_user_debug("copy dummy op from %p to %p", userspaceop, dummy);
    copyret = copy_to_user(userspaceop, dummy, copyamount);
    if (copyret != 0)
      {
        log_user_error(EINVAL, "Unable to copy kernel block thread dummy block_for_request request to userspace, failed to copy %ld bytes", copyret);
        ret = -EINVAL;
        goto error;
      }

    error:
    if (dummy != NULL)
      kfree(dummy);
  }

static void make_operation_block_for_request(device_state *device, unsigned long __user userspace)
  {
    make_operation_return_signal(device, 0, userspace);
  }

static s32 dblock_operation_block_for_request(device_state *device, unsigned long __user userspace)
  {
    s32 ret;
    dblock_context *process_item_context = NULL;

    log_user_debug("start dblock_operation_block_for_request.");

    log_user_debug("about to lock request_block_lock. start dblock_operation_block_for_request.");
    pil_mutex_lock(&device->request_block_lock);

    do
      {
        log_user_debug("concurrent_list_unprocessed_count: %u", device->concurrent_list_unprocessed_count);
        if (device->concurrent_list_unprocessed_count == 0)
          {
            log_user_debug("waiting on request_block_cv");
            pil_cv_wait(&device->request_block_cv, &device->request_block_lock);

            if (signal_pending(current))
              {
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,20,1)
                int signal_number = kernel_dequeue_signal(NULL);
#else
                int signal_number = kernel_dequeue_signal();
#endif
                if (signal_number == SIGURG)
                  continue; // ignore sigurg because go.
                if (signal_number > 0)
                  log_user_error(EINVAL, "Got signal %d waiting for cv", signal_number);
                else
                  log_user_error(EINVAL, "Odd, the kernel said there's a signal pending, but there's no signal to be dequeued, dequeue returned = %d", signal_number);
                log_user_error(-EINTR, "userspace cv_wait for block_cv exited because of signal, unlocking mutex, returning error to ioctl, signal_number %d", signal_number);
                pil_mutex_unlock(&device->request_block_lock);

                make_operation_return_signal(device, signal_number, userspace);

                return -EINTR;
              }
          }
        else
          {
            log_user_debug("unprocessed count > 0, not waiting for request_block_cv");
            break;
          }
      }
    while (device->concurrent_list_unprocessed_count == 0);

    ret = 0;

    find_unprocessed_item(device, &process_item_context);

    if (process_item_context != NULL)
      {
        ret = handle_kernel_request_special(device, userspace, process_item_context);
        if (ret != 0)
          {
            ret = -ENOMEM;
            make_operation_block_for_request(device, userspace);
          }

        log_user_debug("unlocking response lock for operation_id %u", process_item_context->op.operation_id);
        pil_mutex_unlock(&process_item_context->response_lock);
      }
    else
      {
        log_user_error(-ENOENT, "we were woken up/unprocessed count > 0 but there was nothing unprocessed on the concurrent item list to process.");
        ret = -ENOENT;

        log_user_error(-EFAULT, "resetting the unprocessed count to zero since we just counted it and it's zero even though we think it's %u", device->concurrent_list_unprocessed_count);
        device->concurrent_list_unprocessed_count = 0;

        make_operation_block_for_request(device, userspace);
      }
    log_user_debug("dblock_operation_block_for_request unblocked, about to unlock request_block_lock, new unprocessed count: %u", device->concurrent_list_unprocessed_count);
    pil_mutex_unlock(&device->request_block_lock);

    log_user_debug("end dblock_operation_block_for_request which includes the request to userspace, returning: %d", ret);
    log_user_debug("----------------------- end of userspace processing.");
    return ret;
  }

static s32 find_context_by_operation_id(device_state *device, u32 operation_id, dblock_context **out)
  {
    dblock_context *context_ptr;

    log_user_debug("find context by operation_id %d, locking request_block lock", operation_id);
    pil_mutex_lock(&device->request_block_lock);

    context_ptr = NULL;

    list_for_each_entry(context_ptr, &device->concurrent_operations_list, list_anchor)
      {
        log_user_debug("searching operation_id = %d to match request for %d", context_ptr->op.operation_id, operation_id);
        if (context_ptr->op.operation_id == operation_id)
          {
            *out = context_ptr;
            log_user_debug("we found matching operation_id = %u, locking response lock", operation_id);
            pil_mutex_lock(&context_ptr->response_lock);
            pil_mutex_unlock(&device->request_block_lock);
            return 0;
          }
      }

    log_user_error(-ENOENT, "we didn't find operation_id = %d", operation_id);
    pil_mutex_unlock(&device->request_block_lock);
    return -ENOENT;
  }

static s32 dblock_operation_read_response(device_state *device, dblock_operation *op, unsigned long __user userspace)
  {
    s32 respond_ret;
    s32 ret;
    unsigned long copyret;
    dblock_context *context_ptr;
    dblock_operation *userspaceop = (dblock_operation *)userspace;

    char *bio_segment_buffer;
    char *page_buffer;
    char *userspacedatabufferpos;
    u32 pointerpositioncounter;
    dblock_operation_state *bio_segment;
    u32 count;
    s32 userspaceerr;

    respond_ret = 0;

    log_user_debug("start dblock_operation_read_response");

    context_ptr = NULL;
    ret = find_context_by_operation_id(device, op->operation_id, &context_ptr);
    if (ret != 0)
      {
        log_user_error(-ENOENT, "Unable to find concurrent operation_id %u to broadcast to for read_response", op->operation_id);
        log_user_error(-ENOENT, "Will not signal block device thread, because we can't find it.");

        respond_ret = -ENOENT;
        goto errornocontext;
      }

    userspaceerr = op->error;
    if (userspaceerr != 0)
      {
        log_kern_error(-EINVAL, "Error returned from userspace in read response. sending error to kernel side: %d", userspaceerr);
        respond_ret = -EINVAL;
        goto error;
      }

    pointerpositioncounter = 0;
    userspacedatabufferpos = userspaceop->userspacedatabuffer;

    count = 0;
    bio_segment = NULL;
    list_for_each_entry(bio_segment, &context_ptr->bio_segments_op_state_list, list_anchor)
      {
        log_user_debug("copying data from userspace for bio_segment %lld to bio segment buffer.", bio_segment->id);
        count++;
        if (count > context_ptr->number_of_segments_in_list)
          {
            log_user_error(-EOVERFLOW, "we are somehow trying to copy more data than the kernel side said it asked us for %d/%d. Sanity failure.", count, context_ptr->number_of_segments_in_list);
            respond_ret = -EOVERFLOW;
            goto error;
          }

        if (pointerpositioncounter + bio_segment->request_length> MAX_BIO_SEGMENTS_BUFFER_SIZE_PER_REQUEST)
          {
            log_user_error(-EOVERFLOW, "kernel side sent userspace more bio segment DATA than we can fit in the userspace data buffer %lld/%d. Sanity failure.",
                           pointerpositioncounter + bio_segment->request_length, MAX_BIO_SEGMENTS_BUFFER_SIZE_PER_REQUEST);
            respond_ret = -EOVERFLOW;
            goto error;
          }

        page_buffer = kmap(bio_segment->bv_page);
        bio_segment_buffer = page_buffer + bio_segment->offset;

        log_user_debug("Copying data from userspace directly to bio buf: %llu bytes", bio_segment->request_length);

        log_user_debug("copy data from userspace to bio buf %p to %p %lld bytes", userspacedatabufferpos, bio_segment_buffer, bio_segment->request_length);

        copyret = copy_from_user(bio_segment_buffer, userspacedatabufferpos, bio_segment->request_length);
        kunmap(bio_segment->bv_page);
        if (copyret != 0)
          {
            log_user_error(-ENOMEM, "Unable to copy %llu bytes from userspace, %ld didn't copy", bio_segment->request_length, copyret);
            respond_ret = -ENOMEM;
            goto error;
          }

        log_user_debug("userspacedatabufferpos %p, op_state.bio_segment_buffer %p, context_ptr %p", userspacedatabufferpos, bio_segment_buffer, context_ptr);

        userspacedatabufferpos += bio_segment->request_length;
        pointerpositioncounter += bio_segment->request_length;
      }

    error:

    context_ptr->op.error = respond_ret;

    log_user_debug("broadcasting to response_cv to unblock block device thread, and setting triggered flag");
    context_ptr->response_cv_triggered_flag = 1;
    pil_cv_broadcast(&context_ptr->response_cv);
    log_user_debug("about to unlock response_lock");
    pil_mutex_unlock(&context_ptr->response_lock);

    errornocontext:
    log_user_debug("end dblock_operation_read_response, going back to block for another request");
    return dblock_operation_block_for_request(device, userspace);
  }

static s32 dblock_operation_write_response(device_state *device, dblock_operation *op, unsigned long __user userspace)
  {
    s32 respond_ret;
    s32 ret;
    dblock_context *context_ptr;
    s32 userspaceerr;

    respond_ret = 0;

    log_user_debug("start dblock_operation_write_response");

    context_ptr = NULL;
    ret = find_context_by_operation_id(device, op->operation_id, &context_ptr);
    if (ret != 0)
      {
        log_user_error(-ENOENT, "Unable to find concurrent operation_id %u to respond to for write_response", op->operation_id);
        log_user_error(-ENOENT, "Will not signal block device thread, because we can't find it.");

        goto errornocontext;
      }

    userspaceerr = op->error;
    if (userspaceerr != 0)
      {
        log_kern_error(-EINVAL, "Error returned from userspace in write response. sending error to kernel side: %d", userspaceerr);
        respond_ret = -EINVAL;
        goto error;
      }

    log_user_debug("data successfully written by userspace: %llu bytes.", op->packet.write_response.response_total_length_of_all_segment_requests_written);

    error:

    context_ptr->op.error = respond_ret;

    log_user_debug("broadcasting to response_cv to unblock device thread for write response, and setting triggered flag");
    context_ptr->response_cv_triggered_flag = 1;
    pil_cv_broadcast(&context_ptr->response_cv);
    log_user_debug("about to unlock response_lock");
    pil_mutex_unlock(&context_ptr->response_lock);

    errornocontext:
    log_user_debug("end dblock_operation_write_response, going back to block for another request");
    return dblock_operation_block_for_request(device, userspace);
  }

static s32 ioctl_dblock_device_status(unsigned long __user userspace)
  {
    return -ENODATA;
  }

static s32 ioctl_dblock_operation(unsigned long __user userspace)
  {
    unsigned long copyret;
    device_state *device = NULL;
    dblock_operation *userspaceop = (dblock_operation *)userspace;
    u32 operation;

    dblock_operation *holding_area = NULL;
    s32 ret = 0;

    holding_area = kmalloc(sizeof(dblock_operation), GFP_KERNEL);
    if (holding_area == NULL)
      {
        log_kern_error(ENOMEM, "Unable to allocate memory for holding area for ioctl_dblock_operation.");
        ret = -ENOMEM;
        goto error;
      }

    if (data_interrogation)
      {
        log_user_debug("copy userspace op without buffer to holding area %p to %p", userspaceop, holding_area);
      }

    copyret = copy_from_user(holding_area, userspaceop, sizeof(dblock_operation));
    if (copyret != 0)
      {
        log_user_error(-ENOMEM, "Unable to copy %lu bytes from userspace", copyret);
        ret = -ENOMEM;
        goto error;
      }

    ret = find_device_by_handle_id(holding_area->handle_id, &device);
    if (ret != 0)
      {
        log_kern_error(ret, "Unable to find handle_id %d in list of active devices, can't process ioctl.", holding_area->handle_id);

        goto error;
      }

    operation = holding_area->header.operation;

    ret = 0;
    switch (operation)
      {
      case DEVICE_OPERATION_NO_RESPONSE_BLOCK_FOR_REQUEST:
        ret = dblock_operation_block_for_request(device, userspace);
        break;
      case DEVICE_OPERATION_READ_RESPONSE:
        ret = dblock_operation_read_response(device, holding_area, userspace);
        break;
      case DEVICE_OPERATION_WRITE_RESPONSE:
        ret = dblock_operation_write_response(device, holding_area, userspace);
        break;
      default:
        log_user_error(-EINVAL, "Unknown ioctl: %d", operation);
        ret = -EINVAL;
        break;
      }

    device_put(device);

    error:

    if (holding_area != NULL)
      kfree(holding_area);

    return ret;
  }

static long device_ioctl(struct file *f, unsigned int cmd, unsigned long __user userspace)
  {
    s32 ret = 0;
    log_user_debug("start dblock_ioctl");
    log_user_debug("Ioctl: type=%x number=%x  direction=%x  size=%x", _IOC_TYPE(cmd), _IOC_NR(cmd), _IOC_DIR(cmd), _IOC_SIZE(cmd));

    if (cmd == IOCTL_DEVICE_PING)
      {
        log_user_debug("got ioctl_device_ping");
        ret = 0;
      }
    else if (cmd == IOCTL_DEVICE_STATUS)
      ret = ioctl_dblock_device_status(userspace);
    else if (cmd == IOCTL_DEVICE_OPERATION)
      ret = ioctl_dblock_operation(userspace);
    else
      {
        log_user_error(-EINVAL, "Unknown ioctl: %d", cmd);
        ret = -EINVAL;
      }

    log_user_debug("Ioctl end: type=%x number=%x  direction=%x  size=%x", _IOC_TYPE(cmd), _IOC_NR(cmd), _IOC_DIR(cmd), _IOC_SIZE(cmd));
    log_user_debug("end dblock_ioctl");

    return ret;
  }

static int device_getgeo(struct block_device *block_device, struct hd_geometry *geo)
  {
    u64 size;
    s32 retval = 0;
    u32 handle_id = 0;
    device_state *device = NULL;
    struct request_queue *queue = NULL;

    log_kern_debug("starting dblock_getgeo");
    if (block_device == NULL)
      {
        log_kern_error(-EINVAL, "block device is NULL");
        retval = -EINVAL;
        goto error;
      }
    queue = block_device->bd_disk->queue;
    if (queue == NULL)
      {
        log_kern_error(-EINVAL, "no request queue in block device.");
        retval = -EINVAL;
        goto error;
      }
    handle_id = (u32)(size_t)queue->queuedata;
    retval = find_device_by_handle_id(handle_id, &device);
    if (retval != 0)
      {
        log_kern_error(-ENOENT, "no device_state found to process getgeo with.");
        retval = -ENOENT;
        goto error;
      }

    size = device->size;
    do_div(size, KERNEL_SECTOR_SIZE);

    geo->cylinders = (size & ~0x3f) >> 6;
    geo->heads = 4;
    geo->sectors = 16;
    geo->start = 0;

    device_put(device);
    error:

    log_kern_debug("end dblock_getgeo");

    return retval;
  }

static void free_pending_kernel_requests(device_state *device)
  {
    dblock_context *fail_context = NULL;
    log_kern_debug("about to lock request_block_lock so we can mark all the queued items as failures.");
    pil_mutex_lock(&device->request_block_lock);

    log_kern_debug("looking through concurrent operations list for unprocessed items.");

    list_for_each_entry(fail_context, &device->concurrent_operations_list, list_anchor)
      {
        if (fail_context->processed != 0)
          log_kern_debug("operation_id %u already processed, still marking failure", fail_context->op.operation_id);
        else
          {
            log_kern_debug("operation_id %u has not been processed yet, marking it as failure", fail_context->op.operation_id);

            fail_context->processed = 1;

            device->concurrent_list_unprocessed_count--;
            log_kern_debug("decrementing unprocessed count to %u", device->concurrent_list_unprocessed_count);
          }

        log_kern_debug("locking response lock for operation_id %u", fail_context->op.operation_id);
        pil_mutex_lock(&fail_context->response_lock);

        fail_context->op.error = -EBADF;
        log_kern_debug("broadcasting to response_cv to unblock block device thread, and setting triggered flag because of exit");
        fail_context->response_cv_triggered_flag = 1;
        pil_cv_broadcast(&fail_context->response_cv);
        log_kern_debug("about to unlock response_lock for operation_id %u", fail_context->op.operation_id);
        pil_mutex_unlock(&fail_context->response_lock);
      }
    log_kern_debug("done marking queued items as failures and broadcasting to kernel threads, unlocking request_block_lock");
    pil_mutex_unlock(&device->request_block_lock);
  }

static u32 unblock_userspace(device_state *device)
  {
    dblock_context *context;
    s32 ret;
    u32 sleep_counter;
    u32 exit_processed;

    context = NULL;
    log_kern_debug("starting unblock userspace, failing all pending kernel requests...");
    free_pending_kernel_requests(device);

    log_kern_debug("creating concurrent entry to tell userspace to exit.");
    ret = create_concurrent_operation_entry(device, &context);
    if (ret != 0)
      {
        log_kern_error(ret, "unable to create a concurrent operation entry in unblock_userspace.");
        return ret;
      }

    context->op.header.operation = DEVICE_OPERATION_KERNEL_USERSPACE_EXIT;
    context->op.header.size = 0;
    context->op.header.signal_number = 0;

    log_kern_debug("about to lock request_block_lock for unblock userspace adding %u to unprocessed list", context->op.operation_id);
    pil_mutex_lock(&device->request_block_lock);
    device->concurrent_list_unprocessed_count++;
    log_kern_debug("adding userspace exit concurrent entry unprocessed queue.");

    list_add_tail(&(context->list_anchor), &device->concurrent_operations_list);
    log_kern_debug("broadcasting request_block_cv to ioctl thread and setting concurrent_list_unprocessed_count to %u", device->concurrent_list_unprocessed_count);
    pil_cv_broadcast(&device->request_block_cv);
    log_kern_debug("about to unlock request_block_lock");
    pil_mutex_unlock(&device->request_block_lock);

    log_kern_debug("Waiting for userspace to pick up exit queue item.");
    exit_processed = 0;
    for (sleep_counter = 0; sleep_counter < 5; sleep_counter++)
      {
        u32 processed = 0;
        msleep(1);
        pil_mutex_lock(&device->request_block_lock);
        pil_mutex_lock(&context->response_lock);
        processed = context->processed;
        pil_mutex_unlock(&context->response_lock);
        pil_mutex_unlock(&device->request_block_lock);
        if (processed)
          {
            exit_processed = 1;
            log_kern_debug("We found the exit queue item was marked processed, exiting cleanly.");
            break;
          }
      }

    if (exit_processed == 0)
      {
        log_kern_info("we queued an exit item, but it was never picked up. Either userspace is already gone or it is too slow.");
      }

    delete_concurrent_operation_entry(device, context);
    log_kern_debug("end of unblock_userspace.");
    return ret;
  }

static void init_context_item(dblock_context *context)
  {
    s32 structsize;
    pil_mutex_init(&context->response_lock);
    pil_cv_init(&context->response_cv);
    context->response_cv_triggered_flag = 0;
    context->processed = 0;
    INIT_LIST_HEAD(&context->bio_segments_op_state_list);
    memset(&context->list_anchor, 0, sizeof(struct list_head));

    structsize = sizeof(dblock_operation);
    memset(&(context->op), 0, structsize);
  }

static s32 create_concurrent_operation_entry(device_state *device, dblock_context **context)
  {
    u32 op_id;

    log_kern_debug("Creating concurrent operation entry");
    *context = kmalloc(sizeof(dblock_context), GFP_KERNEL);
    if (*context == NULL)
      {
        log_kern_error(ENOMEM, "Unable to allocate a new context for new block device thread operation.");
        return -ENOMEM;
      }

    init_context_item(*context);

    pil_mutex_lock(&device->device_state_lock_mutex);
    op_id = ++device->next_operation_id;
    (*context)->op.operation_id = op_id;

    pil_mutex_unlock(&device->device_state_lock_mutex);
    log_kern_debug("New operation_id: %u", (*context)->op.operation_id);

    return 0;
  }

static void delete_concurrent_operation_entry(device_state *device, dblock_context *context)
  {
    if (context == NULL)
      {
        log_kern_error(-EINVAL, "Delete concurrent operation entry was passed a null context.");
        return;
      }

    log_kern_debug("Deleting concurrent operation entry for operation_id: %u", context->op.operation_id);

    log_kern_debug("about to lock request_block_lock to remove the context item off the list for operation_id %u", context->op.operation_id);
    pil_mutex_lock(&device->request_block_lock);
    log_kern_debug("about to lock response lock");
    pil_mutex_lock(&context->response_lock);

    if (context->processed == 0)
      {

        device->concurrent_list_unprocessed_count--;
        log_kern_debug("also decrementing the unprocessed count to %u because an unprocessed item is being removed from the list.", device->concurrent_list_unprocessed_count);
      }
    pil_mutex_unlock(&context->response_lock);

    list_del(&context->list_anchor);
    pil_mutex_unlock(&device->request_block_lock);

    while (list_empty(&context->bio_segments_op_state_list) == 0)
      {
        dblock_operation_state *op_state;
        op_state = list_first_entry(&context->bio_segments_op_state_list, dblock_operation_state, list_anchor);
        log_kern_debug("concurrent_operation_entry deleting item from head of list of bio_segment_op_states, id: %lld", op_state->id);
        list_del(&op_state->list_anchor);

        kfree(op_state);
      }

    kfree(context);
    log_kern_debug("Context item deleted from list and freed.");
  }

static s32 request_userspace_block_transfer(device_state *device, dblock_context *context)
  {
    s32 block_ret = 0;
    if (context->dir == READ)
      {
        log_kern_debug("starting request userspace block transfer for read: id: %d, number of segments: %u, total bytes in request: %lld",
                       context->op.operation_id, context->number_of_segments_in_list, context->total_data_in_all_segments);

        context->op.header.operation = DEVICE_OPERATION_KERNEL_READ_REQUEST;
        context->op.header.size = 0;
        context->op.header.signal_number = 0;

        context->op.packet.read_request.number_of_segments = context->number_of_segments_in_list;
        context->op.packet.read_request.total_length_of_all_bio_segments = context->total_data_in_all_segments;
      }
    else if (context->dir == WRITE)
      {
        log_kern_debug("starting request userspace block transfer for write: id: %d, number of segments: %u, total bytes in request: %lld",
                       context->op.operation_id, context->number_of_segments_in_list, context->total_data_in_all_segments);

        context->op.header.operation = DEVICE_OPERATION_KERNEL_WRITE_REQUEST;
        context->op.header.size = context->total_data_in_all_segments;
        context->op.header.signal_number = 0;

        context->op.packet.write_request.number_of_segments = context->number_of_segments_in_list;
        context->op.packet.write_request.total_length_of_all_bio_segments = context->total_data_in_all_segments;
      }
    else
      {
        log_kern_error(-EINVAL, "request userspace block transfer request is not a read or write, dir = %d. Failing request for operation_id: %d",
                       context->dir, context->op.operation_id);
        block_ret = -EIO;
        goto errornolock;
      }

    log_kern_debug("about to lock request_block_lock for userspace transfer request. adding operation_id %u to unprocessed list", context->op.operation_id);
    pil_mutex_lock(&device->request_block_lock);

    device->concurrent_list_unprocessed_count++;

    list_add_tail(&(context->list_anchor), &device->concurrent_operations_list);
    log_kern_debug("broadcasting request_block_cv to ioctl thread and setting concurrent_list_unprocessed_count to %u", device->concurrent_list_unprocessed_count);
    pil_cv_broadcast(&device->request_block_cv);

    log_kern_debug("about to lock response_lock. waiting for response from userspace thread, blocking...");

    pil_mutex_lock(&context->response_lock);

    log_kern_debug("about to unlock request_block_lock");

    pil_mutex_unlock(&device->request_block_lock);

    do
      {
        if (context->response_cv_triggered_flag == 0)
          {
            int timedout;
            log_kern_debug("about to wait on response_cv. waiting for response from userspace thread, after we got the response lock...");

            timedout = pil_cv_timedwait(&context->response_cv, &context->response_lock, device->timeout_milliseconds);

            if (signal_pending(current))
              {
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,20,1)
                int signal_number = kernel_dequeue_signal(NULL);
#else
                int signal_number = kernel_dequeue_signal();
#endif
                if (signal_number > 0)
                  log_kern_error(EINVAL, "Got signal %d waiting for cv", signal_number);
                else
                  log_kern_error(EINVAL, "Odd, the kernel said there's a signal pending, but there's no signal to be dequeued, dequeue returned = %d", signal_number);

                if (signal_number == SIGINT)
                  {
                    log_kern_error(-EINTR, "got interrupt signal, returning error for operation_id %u", context->op.operation_id);
                    block_ret = -EINTR;
                    goto error;
                  }

                log_kern_error(-EINTR, "kernel read response_cv_wait exited because of signal, retrying operation_id %u", context->op.operation_id);
                flush_signals(current);
                continue;
              }
            if (timedout != 0)
              {
                log_kern_error(-ETIMEDOUT, "response_cv_wait timedout waiting for userspace response, returning error for operation_id %u", context->op.operation_id);
                block_ret = -ETIMEDOUT;
                goto error;
              }
          }
        else
          log_kern_debug("response triggered flag already set, not waiting for response_cv for operation_id %u", context->op.operation_id);
      }
    while (context->response_cv_triggered_flag == 0);
    context->response_cv_triggered_flag = 0;
    log_kern_debug("about to unlock response_lock that was waiting for response from userspace thread, after the wait...");

    error:

    pil_mutex_unlock(&context->response_lock);

    if (block_ret == 0)
      {
        if (context->op.error != 0)
          {
            log_kern_error(-EIO, "userspace responded to us, but returned error: %d", context->op.error);
            block_ret = -EIO;
          }
        log_kern_debug("got response from userspace thread for operation_id %u", context->op.operation_id);
      }
    errornolock:

    return block_ret;
  }

static s32 add_bio_segment_to_concurrent_operation_entry(dblock_context *context, device_state *device, size_t start_sector, size_t bytes_to_copy, struct page *bv_page, unsigned long offset, u64 counter)
  {
    u64 start;
    dblock_operation_state *bio_segment_op_state;

    log_kern_debug("adding bio segment to concurrent operation entry");
    bio_segment_op_state = kmalloc(sizeof(dblock_operation_state), GFP_KERNEL);
    if (bio_segment_op_state == NULL)
      {
        log_kern_error(ENOMEM, "Unable to allocate a new dblock operation state for bio segment.");
        return -ENOMEM;
      }

    start = (u64)start_sector * (u64)KERNEL_SECTOR_SIZE;

    bio_segment_op_state->bv_page = bv_page;
    bio_segment_op_state->offset = offset;
    bio_segment_op_state->request_start = start;
    bio_segment_op_state->request_length = bytes_to_copy;
    bio_segment_op_state->id = counter;

    list_add_tail(&(bio_segment_op_state->list_anchor), &context->bio_segments_op_state_list);

    return 0;
  }

#if HAVE_BLK_ALLOC_QUEUE_NODE == 1
static blk_qc_t bio_request_handler(struct bio *bio)
#else
static blk_qc_t bio_request_handler(struct request_queue *q, struct bio *bio)
#endif
  {
    struct bio_vec bvec;
    struct bvec_iter iter;
    device_state *device;
    int operation;
    s32 block_ret;
    int total_bytes_to_transfer;
    u32 handle_id;
    u32 buffer_size_tally;
    u32 segments_in_this_concurrent_operation_entry;
    u32 segments_in_entire_bio;
    dblock_context *context;
    s32 ret;
    int dir;
    unsigned long start_time;

    total_bytes_to_transfer = bio_sectors(bio) * KERNEL_SECTOR_SIZE;
    log_kern_debug("start bio_request_handler. total bytes to transfer: %d", total_bytes_to_transfer);

    block_ret = 0;

#if HAVE_BLK_ALLOC_QUEUE_NODE == 1
    handle_id = (u32)(size_t)bio->bi_disk->queue->queuedata;
#else
    handle_id = (u32)(size_t)q->queuedata;
#endif
    block_ret = find_device_by_handle_id(handle_id, &device);
    if (block_ret != 0)
      {
        log_kern_error(-ENOENT, "no device_state found to process request on.");
        block_ret = -ENOENT;
        goto errornodevice;
      }

#if HAVE_BLK_ALLOC_QUEUE_NODE == 1
    disk_stats_start(bio->bi_disk->queue, bio, device->gendisk);
#else
    disk_stats_start(q, bio, device->gendisk);
#endif
    start_time = jiffies;

    if (atomic_read(&device->shutting_down) == STATE_FORCE_SHUTDOWN)
      {
        log_kern_error(-ESHUTDOWN, "device is being shut down can't accept new requests.");
        block_ret = -ESHUTDOWN;
        goto error;
      }

    operation = bio_op(bio);
    if ((operation != REQ_OP_READ) && (operation != REQ_OP_WRITE))
      {
        log_kern_error(-EINVAL, "bio operation is not read or write: %d", operation);
        block_ret = -EINVAL;
        goto error;
      }

    buffer_size_tally = 0;
    segments_in_this_concurrent_operation_entry = 0;
    segments_in_entire_bio = 0;

    log_kern_debug("Starting a concurrent_operation_entry for a list of bio segments");
    context = NULL;
    ret = create_concurrent_operation_entry(device, &context);
    if (ret != 0)
      {
        log_kern_error(ret, "unable to create a concurrent operation entry in bio_request_handler.");
        block_ret = -ENOMEM;
        goto error;
      }

    dir = bio_data_dir(bio);
    context->dir = dir;

    bio_for_each_segment(bvec, bio, iter)
      {
        sector_t sector;

        struct page *bv_page;
        unsigned long offset;
        int bytes_to_transfer;

        sector = iter.bi_sector;

        bv_page = bvec.bv_page;
        offset = bvec.bv_offset;
        bytes_to_transfer = bvec.bv_len;

        if (((segments_in_this_concurrent_operation_entry + 1) > MAX_BIO_SEGMENTS_PER_REQUEST) ||
            buffer_size_tally + bytes_to_transfer > MAX_BIO_SEGMENTS_BUFFER_SIZE_PER_REQUEST ||
            ((segments_in_this_concurrent_operation_entry + 1) > device->max_segments_per_request))
          {

            log_kern_debug("about to add another segment, but we reached maximum capacity for one request to userspace, sending request now...");
            block_ret = request_userspace_block_transfer(device, context);
            if (block_ret != 0)
              {
                log_kern_error(block_ret, "error from request to userspace for partial bio segment list.");
                goto error;
              }

            delete_concurrent_operation_entry(device, context);
            buffer_size_tally = 0;
            segments_in_this_concurrent_operation_entry = 0;

            ret = create_concurrent_operation_entry(device, &context);
            if (ret != 0)
              {
                log_kern_error(ret, "unable to create a followup concurrent operation entry in bio_request_handler.");
                block_ret = -ENOMEM;
                goto error;
              }
            context->dir = dir;
            log_kern_debug("starting the next batch for this bio...");
          }

        log_kern_debug("bio request: segment %d (max %d/%d), start %llu, offset %lu, segment length %d, total bytes in this request %d, dir %d (%s)",
                       segments_in_this_concurrent_operation_entry+1, device->max_segments_per_request, MAX_BIO_SEGMENTS_PER_REQUEST,
                       (u64)sector * KERNEL_SECTOR_SIZE, offset, bytes_to_transfer, buffer_size_tally + bytes_to_transfer,
                       dir, (dir == WRITE ? "write" : "read"));

        segments_in_this_concurrent_operation_entry++;
        segments_in_entire_bio++;
        buffer_size_tally += bytes_to_transfer;
        block_ret = add_bio_segment_to_concurrent_operation_entry(context, device, sector, bytes_to_transfer, bv_page, offset, segments_in_this_concurrent_operation_entry);

        if (block_ret != 0)
          {

            log_kern_error(block_ret, "Error collecting bio segments into a concurrent_operation entry. ending bio with failure.");
            break;
          }

        context->total_data_in_all_segments = buffer_size_tally;
        context->number_of_segments_in_list = segments_in_this_concurrent_operation_entry;
      }

    if (block_ret != 0)
      goto error;

    if (list_empty(&context->bio_segments_op_state_list) == 0)
      {
        log_kern_debug("Finished processing bio segment list, total segments in last batch in concurrent_operation_entry: %d, total segments in bio: %d",
                       segments_in_this_concurrent_operation_entry, segments_in_entire_bio);

        block_ret = request_userspace_block_transfer(device, context);
        if (block_ret != 0)
          {
            log_kern_error(block_ret, "Error collecting final bio segments batch into a concurrent_operation entry. ending bio with failure.");
            goto error;
          }
      }
    else
      log_kern_debug("Finished processing bio segment list, nothing left to do in last batch, total segments in bio: %d", segments_in_entire_bio);

    goto end;

    error:

#if HAVE_BLK_ALLOC_QUEUE_NODE == 1
    disk_stats_end(bio->bi_disk->queue, bio, device->gendisk, start_time);
#else
    disk_stats_end(q, bio, device->gendisk, start_time);
#endif

    device_put(device);

    if (context != NULL)
      delete_concurrent_operation_entry(device, context);

    errornodevice:
    log_kern_debug("ending bio with error.");
    bio->bi_status = BLK_STS_IOERR;
    bio_io_error(bio);
    return BLK_QC_T_NONE;

    end:

    delete_concurrent_operation_entry(device, context);

    log_kern_debug("Completed read for all bio segment requests. ending bio successfully.");
    bio_endio(bio);

    device_put(device);
    return BLK_QC_T_NONE;
  }

static void disk_stats_start(struct request_queue *q, struct bio *bio, struct gendisk *gd)
  {
#if HAVE_BIO_START_IO_ACCT == 1
    bio_start_io_acct(bio);
#else
    generic_start_io_acct(q, bio_op(bio), bio_sectors(bio), &gd->part0);
#endif
  }

static void disk_stats_end(struct request_queue *q,
                           struct bio *bio, struct gendisk *gd,
                           unsigned long start_time)
  {
#if HAVE_BIO_START_IO_ACCT == 1
    bio_end_io_acct(bio, start_time);
#else
    generic_end_io_acct(q, bio_op(bio), &gd->part0, start_time);
#endif
  }


static int device_open(struct block_device *block_device, fmode_t mode)
  {
    device_state *device = NULL;
    s32 retval = 0;
    u32 handle_id = 0;
    struct request_queue *queue = NULL;

    log_kern_debug("start device_open");

    if (block_device == NULL)
      {
        log_kern_error(-EINVAL, "block device is NULL");
        retval = -EINVAL;
        goto error;
      }
    queue = block_device->bd_disk->queue;
    if (queue == NULL)
      {
        log_kern_error(-EINVAL, "no request queue in block device.");
        retval = -EINVAL;
        goto error;
      }
    handle_id = (u32)(size_t)queue->queuedata;
    retval = find_device_by_handle_id(handle_id, &device);
    if (retval != 0)
      {
        log_kern_error(-ENOENT, "no device_state found to process device_open with.");
        retval = -ENOENT;
        goto error;
      }

    pil_mutex_lock(&device->device_state_lock_mutex);

    if (atomic_read(&device->shutting_down) != STATE_RUNNING)
      {
        pil_mutex_unlock(&device->device_state_lock_mutex);
        log_kern_error(-EBUSY, "cannot open device_state while shutting down.");
        retval = -EBUSY;
        goto error;
      }

    device->dev_open_count += 1;
    log_kern_info("Opened dblock, count %d", device->dev_open_count);
    pil_mutex_unlock(&device->device_state_lock_mutex);

    device_put(device);
    error:
    return retval;
  }

static void device_release(struct gendisk *gd, fmode_t mode)
  {
    device_state *device = NULL;
    s32 retval = 0;
    u32 handle_id = 0;
    struct request_queue *queue = NULL;

    log_kern_debug("start device_release");

    if (gd == NULL)
      {
        log_kern_error(-EINVAL, "gendisk is NULL");
        retval = -EINVAL;
        goto error;
      }
    queue = gd->queue;
    if (queue == NULL)
      {
        log_kern_error(-EINVAL, "no request queue in gendisk.");
        retval = -EINVAL;
        goto error;
      }
    handle_id = (u32)(size_t)queue->queuedata;
    retval = find_device_by_handle_id(handle_id, &device);
    if (retval != 0)
      {
        log_kern_error(-ENOENT, "no device_state found to process device_open with.");
        retval = -ENOENT;
        goto error;
      }

    pil_mutex_lock(&device->device_state_lock_mutex);
    device->dev_open_count -= 1;
    log_kern_info("Released dblock, count %d", device->dev_open_count);
    pil_mutex_unlock(&device->device_state_lock_mutex);

    device_put(device);
    error:
    return;
  }

static void block_device_cleanup(device_state *ending_device);
static void remove_device_from_list(device_state *device);
static s32 block_device_destroy(u32 handle_id, u32 force);

static s32 validate_create_params(device_state *new_device, control_block_device_create_params *params)
  {
    s32 retval = 0;
    u32 count = 0;
    device_state *count_ptr;

    new_device->kernel_block_size = params->kernel_block_size;
    if (new_device->kernel_block_size % 4096 != 0)
      {
        log_kern_error(-EINVAL, "kernel block size must be a multiple of 4k, supplied value: %d", new_device->kernel_block_size);
        retval = -EINVAL;
        goto error;
      }

    if ((new_device->kernel_block_size == 0) || (new_device->kernel_block_size  > 4096))
      {
        log_kern_error(-EINVAL, "kernel block size must be more than zero and not more than 4k, supplied value: %d", new_device->kernel_block_size);
        retval = -EINVAL;
        goto error;
      }

    new_device->max_segments_per_request = params->max_segments_per_request;
    if (new_device->max_segments_per_request == 0)
      new_device->max_segments_per_request = MAX_BIO_SEGMENTS_PER_REQUEST;
    if (new_device->max_segments_per_request > MAX_BIO_SEGMENTS_PER_REQUEST)
      new_device->max_segments_per_request = MAX_BIO_SEGMENTS_PER_REQUEST;

    new_device->number_of_blocks = params->number_of_blocks;
    if (new_device->number_of_blocks < CREATE_DEVICE_MIN_NUMBER_BLOCK_COUNT)
      {
        log_kern_error(-ERANGE, "block count must at least %d, supplied value: %lld", CREATE_DEVICE_MIN_NUMBER_BLOCK_COUNT, new_device->number_of_blocks);
        retval = -ERANGE;
        goto error;
      }

    if (new_device->number_of_blocks > CREATE_DEVICE_MAX_NUMBER_BLOCK_COUNT)
      {
        log_kern_error(-ERANGE, "block count must be at most %lld, supplied value: %lld", CREATE_DEVICE_MAX_NUMBER_BLOCK_COUNT, new_device->number_of_blocks);
        retval = -ERANGE;
        goto error;
      }

    new_device->timeout_milliseconds = params->device_timeout_seconds * 1000;
    if (new_device->timeout_milliseconds < (CREATE_DEVICE_MIN_TIMEOUT_SECONDS * 1000))
      {
        log_kern_error(-ERANGE, "timeout seconds must be at least %d, supplied value: %d", CREATE_DEVICE_MIN_TIMEOUT_SECONDS, (new_device->timeout_milliseconds / 1000));
        retval = -ERANGE;
        goto error;
      }
    if (new_device->timeout_milliseconds > (CREATE_DEVICE_MAX_TIMEOUT_SECONDS * 1000))
      {
        log_kern_error(-ERANGE, "timeout seconds must be at most %d, supplied value: %d", CREATE_DEVICE_MAX_TIMEOUT_SECONDS, (new_device->timeout_milliseconds / 1000));
        retval = -ERANGE;
        goto error;
      }

    new_device->device_name = kmalloc(MAX_DEVICE_NAME_LENGTH+1, GFP_KERNEL);
    if (new_device->device_name == NULL)
      {
        log_kern_error(-ENOMEM, "Unable to allocate memory for device name for new device.");
        retval = -ENOMEM;
        goto error;
      }

    strncpy(new_device->device_name, params->device_name, MAX_DEVICE_NAME_LENGTH);
    new_device->device_name[MAX_DEVICE_NAME_LENGTH] = '\0';
    if (strlen(new_device->device_name) == 0)
      {
        log_kern_error(-EINVAL, "Device name must not be empty.");
        retval = -EINVAL;
        goto error;
      }

    count = 0;
    pil_mutex_lock(&master_control_state.control_lock_mutex);
    list_for_each_entry(count_ptr, &master_control_state.active_device_list, list_anchor)
      {
        count++;
      }
    pil_mutex_unlock(&master_control_state.control_lock_mutex);

    if (count >= CREATE_DEVICE_MAX_ACTIVE_BLOCK_DEVICES )
      {
        log_kern_error(-ERANGE, "Can not have more than %d active block devices.", CREATE_DEVICE_MAX_ACTIVE_BLOCK_DEVICES);
        retval = -EINVAL;
        goto error;
      }

    error:
    return retval;
  }

static s32 device_state_init(device_state *new_device)
  {
    u32 copyamount;
    log_kern_debug("new device_state ptr: %p", new_device);
    copyamount = sizeof(dblock_operation);
    log_kern_debug("sizeof dblock.op %zu, size of header and packet going to userspace: %u", sizeof(dblock_operation), copyamount);

    pil_mutex_init(&new_device->device_state_lock_mutex);
    atomic_set(&new_device->in_use, 1);
    new_device->block_device_registered = 0;
    new_device->major = 0;
    new_device->dev_open_count = 0;
    new_device->queue = NULL;
    new_device->gendisk = NULL;
    new_device->size = 0;
    new_device->kernel_block_size = 0;
    new_device->max_segments_per_request = 0;
    new_device->number_of_blocks = 0;
    new_device->timeout_milliseconds = 0;

    INIT_LIST_HEAD(&new_device->concurrent_operations_list);
    new_device->next_operation_id = 0;

    pil_mutex_init(&new_device->request_block_lock);
    pil_cv_init(&new_device->request_block_cv);
    new_device->concurrent_list_unprocessed_count = 0;
    atomic_set(&new_device->shutting_down, STATE_RUNNING);
    new_device->handle_id = 0;

    return 0;
  }

static u32 get_new_device_handle(void)
  {
    u32 ret;
    device_state *device_ptr;
    u32 found;
    log_kern_debug("Locking control lock to get next device handle");
    pil_mutex_lock(&master_control_state.control_lock_mutex);
    ret = master_control_state.next_device_handle++;
    if (ret == 0)
      ret = master_control_state.next_device_handle++;
    while (1)
      {
        found = 0;
        log_kern_debug("looking through active device list...");
        list_for_each_entry(device_ptr, &master_control_state.active_device_list, list_anchor)
          {
            log_kern_debug("list has handle_id %d", device_ptr->handle_id);
            if (device_ptr->handle_id == ret)
              {
                found = 1;
                log_kern_debug("handle_id %d is duplicate, try another one", device_ptr->handle_id);
                break;
              }
          }
        if (found == 0)
          break;

        ret = master_control_state.next_device_handle++;
        if (ret == 0)
          ret = master_control_state.next_device_handle++;
      }
    pil_mutex_unlock(&master_control_state.control_lock_mutex);
    log_kern_debug("new handle_id is %d", ret);
    return ret;
  }

static s32 preflight_add_disk(unsigned char *device_name)
  {
    struct file *fp = NULL;
    s32 retval = 0;
    unsigned char *buf = NULL;
    buf = kmalloc(strlen(device_name) + 20, GFP_KERNEL);
    if (buf == NULL)
      {
        log_kern_error(-ENOMEM, "can't allocate memory for preflight check.");
        retval = -ENOMEM;
        goto end;
      }
    strcpy(buf, "/dev/");
    strcat(buf, device_name);
    log_kern_debug("checking for existence of %s", buf);

    fp = filp_open(buf, O_RDONLY, 0);
    if ((IS_ERR(fp) || fp == NULL) == 0)
      {
        log_kern_error(-EEXIST, "preflight check: %s already exists.", buf);
        retval = -EEXIST;
        goto end;
      }
    else
      fp = NULL;

    end:
    if (fp != NULL)
      {
        filp_close(fp, NULL);
      }
    if (buf != NULL)
      kfree(buf);
    return retval;
  }

static const struct file_operations dblock_io_device_fops = {
    .owner      = THIS_MODULE,
    .llseek     = no_llseek,
    .unlocked_ioctl = device_ioctl,
};

static s32 create_io_device(device_state *new_device)
  {
    s32 retval = 0;
    char *name = kzalloc(strlen(new_device->device_name) + 5, GFP_KERNEL);
    if (!name)
      {
        log_kern_error(-ENOMEM, "failed to create buffer for io_dev_name.");
        retval = -ENOMEM;
        goto error;
      }

    sprintf(name, "%s-ctl", new_device->device_name);
    new_device->io_dev.minor = MISC_DYNAMIC_MINOR;
    new_device->io_dev.name = name;
    new_device->io_dev.fops = &dblock_io_device_fops;
    new_device->io_dev_name = name;

    retval = misc_register(&new_device->io_dev);
    if (retval) {
        log_kern_error(retval, "error registering io device for '%s'", new_device->device_name);
        goto error;
    }

    return 0;

    error:

    log_kern_error(retval, "failed to create io device for '%s'", new_device->device_name);
    new_device->io_dev.minor = 0;
    new_device->io_dev.name = NULL;
    new_device->io_dev.fops = NULL;
    new_device->io_dev_name = NULL;
    kfree(name);
    return retval;
  }

static s32 ioctl_block_device_create(unsigned long __user userspace)
  {
    u64 bytes;
    u64 sectors;
    s32 retval = 0;
    u32 handle_id = 0;
    unsigned long copyret;
    device_state *new_device = NULL;
    control_operation *userspaceparams = (control_operation *)userspace;
    control_operation params;

    copyret = copy_from_user(&params, userspaceparams, sizeof(control_operation));
    if (copyret != 0)
      {
        log_kern_error(-EINVAL, "unable to copy parameters from userspace for block device create.");
        retval = -EINVAL;
        goto error;
      }

    new_device = kzalloc(sizeof(device_state), GFP_KERNEL);
    if (new_device == NULL)
      {
        log_kern_error(-ENOMEM, "Unable to allocate device state structure for new device.");
        retval = -ENOMEM;
        goto error;
      }

    retval = device_state_init(new_device);
    if (retval != 0)
      {
        log_kern_error(retval, "unable to init device state for new device");
        goto error;
      }

    retval = validate_create_params(new_device, &params.create_params);
    if (retval != 0)
      goto error;

    new_device->size = (u64)params.create_params.number_of_blocks * (u64)params.create_params.kernel_block_size;
    log_kern_debug("new device kernel block size in bytes: %d", new_device->kernel_block_size);
    log_kern_debug("new device number of kernel block size blocks: %lld", new_device->number_of_blocks);
    log_kern_debug("new device total block device size in bytes: %lld", new_device->size);

    retval = create_io_device(new_device);
    if (retval != 0)
      goto error;

    retval = preflight_add_disk(new_device->device_name);
    if (retval != 0)
      goto error;

    handle_id = get_new_device_handle();
    new_device->handle_id = handle_id;

#if HAVE_BLK_ALLOC_QUEUE_NODE == 1
    new_device->queue = blk_alloc_queue(NUMA_NO_NODE);
#elif HAVE_COMBINED_BLK_ALLOC_QUEUE == 1
    new_device->queue = blk_alloc_queue(bio_request_handler, NUMA_NO_NODE);
#else
    new_device->queue = blk_alloc_queue(GFP_KERNEL);
#endif
    if (new_device->queue == NULL)
      {
        log_kern_error(-ENOMEM, "Unable to allocate request queue for new block device");
        retval = -ENOMEM;
        goto error;
      }

#if HAVE_COMBINED_BLK_ALLOC_QUEUE == 0 && HAVE_BLK_ALLOC_QUEUE_NODE == 0
    blk_queue_make_request(new_device->queue, bio_request_handler);
#endif

    blk_queue_logical_block_size(new_device->queue, new_device->kernel_block_size);

    new_device->queue->queuedata = (void *)(size_t)new_device->handle_id;

    new_device->block_device_registered = 0;
    new_device->major = register_blkdev(0, new_device->device_name);
    if (new_device->major < 0)
      {
        log_kern_error(-ENOMEM, "Unable to register dblock block device");
        retval = -ENOMEM;
        goto error;
      }
    new_device->block_device_registered = 1;
    log_kern_info("dblock major number %d", new_device->major);

    new_device->gendisk = alloc_disk(max_minors);
    if (new_device->gendisk == NULL)
      {
        log_kern_error(-ENOMEM, "alloc_disk failure");
        retval = -ENOMEM;
        goto error;
      }

    new_device->gendisk->major = new_device->major;
    new_device->gendisk->first_minor = 0;
    new_device->gendisk->fops = &dblock_blk_dev_ops;
    new_device->gendisk->queue = new_device->queue;

    // This flag disables partitions scanning. Normally, the kernel will try to read from the
    // device to find partitions before add_disk() ends. This is a problem for us because the
    // userspace program cannot attach to the device until add_disk() returns, meaning this IO
    // can't be done. This does mean that the user will have to manually partprobe the device
    // afterwards.
    new_device->gendisk->flags = GENHD_FL_NO_PART_SCAN;
    new_device->gendisk->private_data = new_device;

    strncpy(new_device->gendisk->disk_name, new_device->device_name, MAX_DEVICE_NAME_LENGTH);

    bytes = new_device->size;
    sectors = bytes;
    do_div(sectors, KERNEL_SECTOR_SIZE);
    set_capacity(new_device->gendisk, sectors);
    log_kern_debug("number of 512-byte sectors: %lld", sectors);

    new_device->dev_open_count = 0;

    pil_mutex_lock(&master_control_state.control_lock_mutex);

    list_add_tail(&new_device->list_anchor, &master_control_state.active_device_list);
    params.create_params.handle_id = new_device->handle_id;

    pil_mutex_unlock(&master_control_state.control_lock_mutex);
    log_kern_debug("calling add_disk for new device: %s, handle_id: %d", new_device->device_name, new_device->handle_id);
    add_disk(new_device->gendisk);

    goto end;

    error:

    block_device_cleanup(new_device);

    end:

    params.create_params.error = retval;

    copyret = copy_to_user(userspaceparams, &params, sizeof(control_block_device_create_params));
    if (copyret != 0)
      {
        log_kern_error(-EINVAL, "unable to copy parameters back to userspace for block device create response, destroying block device.");

        block_device_destroy(handle_id, 1);
        retval = -EINVAL;
      }

    return retval;
  }

static void device_state_cleanup(device_state *ending_device)
  {
    dblock_context *context_ptr;
    pil_cv_destroy(&ending_device->request_block_cv);

    log_kern_info("device state cleanup, freeing concurrent_operations_list");
    context_ptr = NULL;

    pil_mutex_lock(&ending_device->request_block_lock);
    while (list_empty(&ending_device->concurrent_operations_list) == 0)
      {
        context_ptr = list_first_entry(&ending_device->concurrent_operations_list, struct dblock_context_t, list_anchor);
        log_kern_debug("block_device_cleanup deleting item from head of list operation_id: %u", context_ptr->op.operation_id);
        list_del(&context_ptr->list_anchor);

        kfree(context_ptr);
      }
    pil_mutex_unlock(&ending_device->request_block_lock);
  }

static void io_device_cleanup(device_state *ending_device)
  {
    misc_deregister(&ending_device->io_dev);
    kfree(ending_device->io_dev_name);
  }

static void block_device_cleanup(device_state *ending_device)
  {
    log_kern_info("Cleaning block device");
    if (ending_device == NULL)
      {
        log_kern_debug("No block device to clean.");
        return;
      }

    device_state_cleanup(ending_device);
    if (ending_device->gendisk != NULL)
      {
        log_kern_debug("del_gendisk");
        del_gendisk(ending_device->gendisk);
        put_disk(ending_device->gendisk);
      }

    if (ending_device->block_device_registered != 0)
      {
        log_kern_debug("unregister block device.");
        unregister_blkdev(ending_device->major, ending_device->device_name);
        ending_device->block_device_registered = 0;
      }

    if (ending_device->device_name != NULL)
      {
        log_kern_debug("Freeing device name. name is: %s", ending_device->device_name);
        kfree(ending_device->device_name);
      }

    if (ending_device->io_dev_name != NULL)
      {
        log_kern_debug("cleaning up io device. name is %s", ending_device->io_dev_name);
        io_device_cleanup(ending_device);
      }

    if (ending_device->queue != NULL)
      {
        log_kern_debug("block cleanup queue.");

        blk_cleanup_queue(ending_device->queue);
      }

    log_kern_debug("free device state memory.");
    kfree(ending_device);
  }

static void remove_device_from_list(device_state *device)
  {
    if (device == NULL)
      {
        log_kern_error(-EINVAL, "remove_device_from_list was called with NULL");
        return;
      }
    pil_mutex_lock(&master_control_state.control_lock_mutex);

    log_kern_info("remove_device_from_list, removing active device handle_id: %d, %s", device->handle_id, device->device_name);
    list_del(&device->list_anchor);
    pil_mutex_unlock(&master_control_state.control_lock_mutex);

    device_put(device);
  }

static s32 find_device_by_handle_id(u32 handle_id, device_state **deviceout)
  {
    device_state *device = NULL;
    u32 found = 0;
    *deviceout = NULL;

    log_kern_debug("locking master control lock to find device by handle_id: %d", handle_id);
    pil_mutex_lock(&master_control_state.control_lock_mutex);
    list_for_each_entry(device, &master_control_state.active_device_list, list_anchor)
      {
        if (device->handle_id == handle_id)
          {
            found = 1;
            *deviceout = device;

            log_kern_debug("found device, inc device in_use count for handle_id %d while holding master to control lock", handle_id);
            device_get(device);
            break;
          }
      }
    pil_mutex_unlock(&master_control_state.control_lock_mutex);

    if (found == 0)
      {
        log_kern_error(-ENOENT, "couldn't find device by handle_id %d", handle_id);
        return -ENOENT;
      }
    return 0;
  }

static s32 ioctl_block_device_destroy_by_id(unsigned long __user userspace)
  {
    s32 retval = 0;
    u32 handle_id = 0;
    unsigned long copyret;
    control_operation *userspaceparams = (control_operation *)userspace;
    control_operation params;

    copyret = copy_from_user(&params, userspaceparams, sizeof(control_operation));
    if (copyret != 0)
      {
        log_kern_error(-EINVAL, "unable to copy parameters from userspace to block device destroy by id.");
        retval = -EINVAL;
        goto error;
      }

    handle_id = params.destroy_params_by_id.handle_id;
    log_kern_debug("attempting to destroy block device with handle_id %d", handle_id);
    retval = block_device_destroy(handle_id, params.destroy_params_by_id.force);
    if (retval != 0)
      log_kern_error(retval, "Unable to destroy block device with handle_id %d", handle_id);

    goto end;

    error:
    end:

    params.destroy_params_by_id.error = retval;

    copyret = copy_to_user(userspaceparams, &params, sizeof(control_block_device_destroy_by_id_params));
    if (copyret != 0)
      {
        log_kern_error(-EINVAL, "unable to copy parameters back to userspace for block device destroy by id response.");

        retval = -EINVAL;
      }

    return retval;
  }

static s32 ioctl_block_device_destroy_by_name(unsigned long __user userspace)
  {
    s32 retval = 0;
    unsigned char device_name[MAX_DEVICE_NAME_LENGTH+1];
    u32 handle_id = 0;
    device_state *device_ptr;

    unsigned long copyret;
    control_operation *userspaceparams = (control_operation *)userspace;
    control_operation params;

    copyret = copy_from_user(&params, userspaceparams, sizeof(control_operation));
    if (copyret != 0)
      {
        log_kern_error(-EINVAL, "unable to copy parameters from userspace to block device destroy by name.");
        retval = -EINVAL;
        goto error;
      }

    strncpy(device_name, params.destroy_params_by_name.device_name, MAX_DEVICE_NAME_LENGTH);
    device_name[MAX_DEVICE_NAME_LENGTH] = '\0';
    if (strlen(device_name) == 0)
      {
        log_kern_error(-EINVAL, "Device name must not be empty.");
        retval = -EINVAL;
        goto error;
      }

    handle_id = 0;
    pil_mutex_lock(&master_control_state.control_lock_mutex);
    list_for_each_entry(device_ptr, &master_control_state.active_device_list, list_anchor)
      {
        if (strcmp(device_ptr->device_name, device_name) == 0)
          {
            handle_id = device_ptr->handle_id;
            break;
          }
      }
    pil_mutex_unlock(&master_control_state.control_lock_mutex);
    if (handle_id == 0)
      {
        log_kern_error(-ENOENT, "Device name %s not found", device_name);
        retval = -ENOENT;
        goto error;
      }

    log_kern_debug("attempting to destroy block device %s with handle_id %d", device_name, handle_id);
    retval = block_device_destroy(handle_id, params.destroy_params_by_name.force);
    if (retval != 0)
      log_kern_error(retval, "Unable to destroy block device with handle_id %d", handle_id);

    goto end;

    error:
    end:

    params.destroy_params_by_name.error = retval;

    copyret = copy_to_user(userspaceparams, &params, sizeof(control_block_device_destroy_by_name_params));
    if (copyret != 0)
      {
        log_kern_error(-EINVAL, "unable to copy parameters back to userspace for block device destroy by name response.");

        retval = -EINVAL;
      }

    return retval;
  }

static void sync_gendisk(struct gendisk *disk)
  {
    struct disk_part_iter piter;
	  struct hd_struct *part;

    disk_part_iter_init(&piter, disk, 0);
    while ((part = disk_part_iter_next(&piter))) {
      struct block_device *bdev = NULL;

      bdev = bdget_disk(disk, part->partno);
      if (!bdev)
        continue;

      log_kern_info("syncing partition: %d", part->partno);

      fsync_bdev(bdev);
      bdput(bdev);
    }
    disk_part_iter_exit(&piter);
  }

static s32 block_device_destroy(u32 handle_id, u32 force)
{
    s32 retval = 0;
    device_state *device = NULL;

    log_kern_info("block device destroy handle_id: %u force = %u", handle_id, force);
    retval = find_device_by_handle_id(handle_id, &device);
    if (retval != 0)
      {
        log_kern_error(-ENOENT, "no device_state found to process block_device_destroy with.");
        retval = -ENOENT;
        goto error;
      }

    pil_mutex_lock(&device->device_state_lock_mutex);

    if (!force && device->dev_open_count != 0)
      {
        pil_mutex_unlock(&device->device_state_lock_mutex);
        log_kern_error(-EBUSY, "cannot shut down device while it is open. Current count = %u", device->dev_open_count);
        retval = -EBUSY;
        goto error_with_device;
      }

    atomic_set(&device->shutting_down, (force) ? STATE_FORCE_SHUTDOWN : STATE_SHUTDOWN);
    log_kern_info("Set shutdown flag");

    pil_mutex_unlock(&device->device_state_lock_mutex);

    sync_gendisk(device->gendisk);

    remove_device_from_list(device);

    log_kern_info("destroy device %s, unblocking userspace.", device->device_name);
    unblock_userspace(device);

    error_with_device:
    device_put(device);

    error:
    return retval;
}

static s32 ioctl_block_device_get_handle_id_by_name(unsigned long __user userspace)
  {
    s32 retval = 0;
    unsigned char device_name[MAX_DEVICE_NAME_LENGTH+1];
    u32 handle_id = 0;
    device_state *device_ptr;

    unsigned long copyret;
    control_operation *userspaceparams = (control_operation *)userspace;
    control_operation params;

    copyret = copy_from_user(&params, userspaceparams, sizeof(control_operation));
    if (copyret != 0)
      {
        log_kern_error(-EINVAL, "unable to copy parameters from userspace for get handle_id by name.");
        retval = -EINVAL;
        goto error;
      }

    strncpy(device_name, params.get_handle_id_params_by_name.device_name, MAX_DEVICE_NAME_LENGTH);
    device_name[MAX_DEVICE_NAME_LENGTH] = '\0';
    if (strlen(device_name) == 0)
      {
        log_kern_error(-EINVAL, "Device name must not be empty.");
        retval = -EINVAL;
        goto error;
      }

    handle_id = 0;
    pil_mutex_lock(&master_control_state.control_lock_mutex);
    list_for_each_entry(device_ptr, &master_control_state.active_device_list, list_anchor)
      {
        if (strcmp(device_ptr->device_name, device_name) == 0)
          {
            handle_id = device_ptr->handle_id;
            break;
          }
      }
    pil_mutex_unlock(&master_control_state.control_lock_mutex);
    if (handle_id == 0)
      {
        log_kern_error(-ENOENT, "Device name %s not found", device_name);
        retval = -ENOENT;
        goto error;
      }

    log_kern_debug("found handle_id %d for block device %s", handle_id, device_name);
    params.get_handle_id_params_by_name.handle_id = handle_id;
    goto end;

    error:
    end:

    params.get_handle_id_params_by_name.error = retval;

    copyret = copy_to_user(userspaceparams, &params, sizeof(control_block_device_get_handle_id_by_name_params));
    if (copyret != 0)
      {
        log_kern_error(-EINVAL, "unable to copy parameters back to userspace for block device get handle_id by name response.");

        retval = -EINVAL;
      }

    return retval;
  }

static s32 ioctl_block_device_destroy_all_devices_kernel(control_operation *params)
  {
    s32 retval = 0;
    device_state *device = NULL;
    int lp;
    int count = 0;
    u32 handle_id = 0;

    log_kern_info("master control state destroy, including cleaning up orphaned devices kernel.");

    pil_mutex_lock(&master_control_state.control_lock_mutex);
    list_for_each_entry(device, &master_control_state.active_device_list, list_anchor)
      {
        count++;
      }
    pil_mutex_unlock(&master_control_state.control_lock_mutex);
    log_kern_debug("master_control_state_destroy: there are %d active devices", count);

    for (lp = 0; lp < count; lp++)
      {
        device = NULL;
        pil_mutex_lock(&master_control_state.control_lock_mutex);
        if (list_empty(&master_control_state.active_device_list) == 0)
          {
            device = list_first_entry(&master_control_state.active_device_list, device_state, list_anchor);
            log_kern_debug("found orphaned device: %s", (device->device_name == NULL ? "unknown" : device->device_name));
            handle_id = device->handle_id;
          }
        pil_mutex_unlock(&master_control_state.control_lock_mutex);
        if (device != NULL)
          {
            s32 ret = block_device_destroy(handle_id, params->destroy_params_all.force);
            if (ret != 0)
              {
                log_kern_error(EINVAL, "unable to destroy block device, handle id %d", handle_id);
                retval = ret;
              }
          }
      }
    return retval;
  }


static s32 ioctl_block_device_destroy_all_devices(unsigned long __user userspace)
  {
    unsigned long copyret;
    control_operation params;
    control_operation *userspaceparams = (control_operation *)userspace;

    log_kern_info("master control state destroy, including cleaning up orphaned devices.");
    copyret = copy_from_user(&params, userspaceparams, sizeof(control_operation));
    if (copyret != 0)
      {
        log_kern_error(-EINVAL, "unable to copy parameters from userspace to block device destroy all devices.");
        return -EINVAL;
      }

    return ioctl_block_device_destroy_all_devices_kernel(&params);
  }


static long control_device_ioctl(struct file *f, unsigned int cmd, unsigned long __user l);
static void master_control_state_destroy(void);
static void master_control_state_init(void);
static void control_device_destroy(void);
static s32 control_device_create(void);

static const struct file_operations dblock_control_device_fops = {
    .owner      = THIS_MODULE,
    .llseek     = no_llseek,
    .unlocked_ioctl = control_device_ioctl,

};

struct miscdevice dblock_control_device = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = DBLOCK_CONTROL_DEVICE_NAME ,
    .fops = &dblock_control_device_fops,
};

static long control_device_ioctl(struct file *f, unsigned int cmd, unsigned long __user l)
  {
    s32 retval = 0;
    log_kern_debug("start control_device_ioctl");

    if (cmd == IOCTL_CONTROL_PING)
      {
        log_kern_debug("got ioctl_control_ping");
        retval = 0;
      }
    else if (cmd == IOCTL_CONTROL_STATUS)
      {
        log_kern_debug("got ioctl_control_status");
        retval = -ENODATA;
      }
    else if (cmd == IOCTL_CONTROL_CREATE_DEVICE)
      {
        log_kern_debug("got ioctl_control_create_device");
        retval = ioctl_block_device_create(l);
      }
    else if (cmd == IOCTL_CONTROL_DESTROY_DEVICE_BY_ID)
      {
        log_kern_debug("got ioctl_control_destroy_device_by_id");
        retval = ioctl_block_device_destroy_by_id(l);
      }
    else if (cmd == IOCTL_CONTROL_DESTROY_DEVICE_BY_NAME)
      {
        log_kern_debug("got ioctl_control_destroy_device_by_name");
        retval = ioctl_block_device_destroy_by_name(l);
      }
    else if (cmd == IOCTL_CONTROL_DESTROY_ALL_DEVICES)
      {
        log_kern_debug("got ioctl_control_destroy_all_devices");
        retval = ioctl_block_device_destroy_all_devices(l);
      }
    else if (cmd == IOCTL_CONTROL_GET_HANDLE_ID_BY_NAME)
      {
        log_kern_debug("got ioctl_control_get_handle_id_by_name");
        retval = ioctl_block_device_get_handle_id_by_name(l);
      }
    else
      {
        log_kern_error(-EINVAL, "Unknown ioctl for control device: %d", cmd);
        retval = -EINVAL;
      }

    log_kern_debug("end control_device_ioctl");

    return retval;
  }

static s32 control_device_create()
  {
    s32 error;
    error = misc_register(&dblock_control_device);
    if (error) {
        log_kern_error(error, "error on misc_register %d", error);
        return error;
    }

    log_kern_info("created control device ");
    return 0;
  }

static void control_device_destroy()
  {
    misc_deregister(&dblock_control_device);
    log_kern_info("destroyed dblock control device");
    return;
  }

static void master_control_state_init()
  {
    log_kern_debug("Init master control state.");
    pil_mutex_init(&master_control_state.control_lock_mutex);
    INIT_LIST_HEAD(&master_control_state.active_device_list);
    master_control_state.next_device_handle = 1;
  }

static void master_control_state_destroy()
  {
    control_operation co;
    memset(&co, 0, sizeof(control_operation));
    co.destroy_params_all.force = 1;
    if (ioctl_block_device_destroy_all_devices_kernel(&co) != 0)
      log_kern_error(EINVAL, "destroy all block devices failed");
  }

static int __init dblock_init(void)
  {
    int ret;
    log_kern_info("init dblock. build: %s", DBLOCK_VERSION);
    log_kern_info("control device name: %s", DBLOCK_CONTROL_DEVICE_NAME);
    log_kern_debug("u8: %zu, u16: %zu, u32: %zu, u64: %zu, int: %zu, v*: %zu, ushort %zu, size_t %zu",
                   sizeof(u8), sizeof(u16) ,sizeof(u32), sizeof(u64), sizeof(int), sizeof(void *),
                   sizeof(unsigned short), sizeof(size_t));
    master_control_state_init();

    ret = control_device_create();
    if (ret != 0)
        return ret;

    return 0;
  }

static void dblock_exit(void)
  {
    log_kern_info("dblock_exit starting.");
    control_device_destroy();
    master_control_state_destroy();
    log_kern_info("dblock_exit completed, module free to unload.");
  }

module_init(dblock_init);
module_exit(dblock_exit);

MODULE_VERSION(DBLOCK_VERSION);
MODULE_LICENSE(DBLOCK_LICENSE);
MODULE_AUTHOR(DBLOCK_AUTHOR);
MODULE_DESCRIPTION(DBLOCK_DESC);


