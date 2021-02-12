// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2020-2021 Datto Inc.
 */

#include <stdarg.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <memory>
#include <vector>
#include <map>
#include "string.h"

#include "../dblockshare.h"

using std::string;
using std::map;
using std::shared_ptr;
using std::vector;

#define TXT_DEVICE_NAME "dblockramdisk"
#define TXT_ZOSBD2_CONTROL_DEVICE_NAME "dblockctl"

const int MAX_ERRSTR = 1024;

class Ret
  {
  public:

    static int r()
      {
        return 0;
      }

    static int r(int errcode, const char *format, ...)
      {
        va_list args;
        char out[MAX_ERRSTR] =
          { 0 };

        va_start(args, format);

        int len = vsnprintf(NULL, 0, format, args);
        if (len > 0)
          {
            va_end(args);
            va_start(args, format);
            vsnprintf(out, MAX_ERRSTR, format, args);
          }
        va_end(args);

        if (errcode == 0)
          errcode = -1;
        printf("%s\n", out);
        return errcode;
      }
  };

class libdblock
  {
  public:

    std::map<u64, std::string> ramdisk;

    u32 m_block_device_handle_id;

    int open_bd(std::string device_name, int &fdout)
      {
        fdout = open(device_name.c_str(), O_RDWR);
        if (fdout == -1)
          return Ret::r(errno, "unable to open block control/device %s, err: %d", device_name.c_str(), errno);
        return Ret::r();
      }

    int safe_ioctl(int fd, unsigned long cmd, void *data)
      {
        int r = ioctl(fd, cmd, data);
        if (r == -1)
          return Ret::r(errno, "unable to make ioctl call for fd: %d, cmd %d, err: %d", fd, cmd, errno);
        return Ret::r();
      }

    void set_create_params_device_name(control_operation &co, string device_name)
      {
        strncpy((char*)co.create_params.device_name, device_name.c_str(), MAX_DEVICE_NAME_LENGTH);

        co.create_params.device_name[MAX_DEVICE_NAME_LENGTH] = '\0';
      }

    int create_block_device(int fd, const string &device_name, u32 block_size, u64 number_of_kernel_blocks, u32 device_timeout_seconds, u32 &handle_id_out)
      {
        printf("creating block device: %s, kernel block size: %d, number of blocks: %lld, total device size bytes: %lld, device timeout seconds: %ud\n", device_name.c_str(),
               block_size, number_of_kernel_blocks, (u64)block_size * (u64)number_of_kernel_blocks, device_timeout_seconds);

        control_operation op_create;

        set_create_params_device_name(op_create, device_name);
        op_create.create_params.kernel_block_size = block_size;
        op_create.create_params.number_of_blocks = number_of_kernel_blocks;
        op_create.create_params.device_timeout_seconds = device_timeout_seconds;
        op_create.create_params.max_segments_per_request = 0;

        int r = safe_ioctl(fd, IOCTL_CONTROL_CREATE_DEVICE, &op_create);
        if (r != 0)
          return Ret::r(errno, "ioctl call to create block device failed, errorcode %d, create error: %d", errno, op_create.create_params.error);

        u32 handle_id = op_create.create_params.handle_id;
        printf("create block device for %s successful, handle_id: %d\n", device_name.c_str(), handle_id);
        handle_id_out = handle_id;

        return Ret::r();
      }

    int destroy_block_device()
      {
        int fdctl;
        string control_device_name = TXT_ZOSBD2_CONTROL_DEVICE_NAME;
        string full_control_device_name = "/dev/" + control_device_name;
        int retval = open_bd(full_control_device_name, fdctl);
        if (retval != 0)
          return retval;
        shared_ptr<int> x(NULL, [&](int*)
          { close(fdctl);});

        return destroy_all_block_devices(fdctl);
      }

    int destroy_all_block_devices(int fd)
      {
        printf("destroying all block devices.\n");

        control_operation op_destroy;
        memset(&op_destroy, 0, sizeof(control_operation));
        op_destroy.destroy_params_all.force = 1;
        int r = safe_ioctl(fd, IOCTL_CONTROL_DESTROY_ALL_DEVICES, &op_destroy);
        if (r != 0)
          return Ret::r(errno, "ioctl call to destroy all block devices failed, errorcode %d", errno);

        printf("destroy all block devices successful\n");

        return Ret::r();
      }

    int validate_read_request(u32 handle_id, dblock_operation &requestop)
      {
        if (requestop.packet.read_request.number_of_segments == 0)
          return Ret::r(-EINVAL, "invalid read request, number of segments is zero.");
        if (requestop.packet.read_request.number_of_segments > MAX_BIO_SEGMENTS_PER_REQUEST)
          return Ret::r(-EINVAL, "invalid read request, number of segments is greater than %d", MAX_BIO_SEGMENTS_PER_REQUEST);

        return Ret::r();
      }

    int block_for_request(int fd, u32 handle_id, dblock_operation &op)
      {
        op.handle_id = handle_id;
        op.header.operation = DEVICE_OPERATION_NO_RESPONSE_BLOCK_FOR_REQUEST;
        op.header.size = 0;

        int retval = safe_ioctl(fd, IOCTL_DEVICE_OPERATION, &op);
        if (retval != 0)
          return Ret::r(errno, "ioctl device operation call failed for block_for_request, error: %d", errno);
        return Ret::r();
      }

    int read_block(u64 start_in_bytes, u64 length, void *data)
      {
        while (length > 0)
          {
            map<u64, string>::iterator it = ramdisk.find(start_in_bytes);
            if (it == ramdisk.end())
              {
                memset(data, 0, 4096);
              }
            else
              {
                string &d = it->second;
                const char *b = d.c_str();
                memcpy(data, b, 4096);
              }
            data = (char*)data + 4096;
            start_in_bytes += 4096;
            length -= 4096;
          }

        return Ret::r();
      }

    int write_block(u64 start_in_bytes, u64 length, const void *data)
      {
        while (length > 0)
          {
            string d((const char*)data, 4096);
            ramdisk[start_in_bytes] = d;
            data = (char*)data + 4096;
            start_in_bytes += 4096;
            length -= 4096;
          }
        return Ret::r();
      }

    int respond_to_read_request(int fd, u32 handle_id, dblock_operation &requestop)
      {
        int retval = validate_read_request(handle_id, requestop);
        if (retval != 0)
          return retval;
        u32 operation_id = requestop.operation_id;
        u64 number_of_segments = requestop.packet.read_request.number_of_segments;

        dblock_operation &responseop = requestop;

        responseop.handle_id = handle_id;
        responseop.operation_id = operation_id;
        responseop.error = 0;
        responseop.header.operation = DEVICE_OPERATION_READ_RESPONSE;
        responseop.header.size = 0;

        retval = 0;

        bool verify_start_first = true;
        u64 verify_start = 0;
        u64 entire_start = 0;
        u32 entire_length = 0;

        for (u32 lp = 0; lp < number_of_segments; lp++)
          {
            dblock_bio_segment_metadata *entry = &requestop.metadata[lp];
            u64 start = entry->start;
            u64 length = entry->length;
            if (verify_start_first == true)
              {
                verify_start_first = false;
                verify_start = start;
                entire_start = start;
              }
            else if (verify_start != start)
              return Ret::r(-EINVAL, "respond_to_read_request segments are not contiguous, expected start %lld got start %lld", verify_start, start);

            verify_start += length;
            entire_length += length;
          }

        unsigned char *userspacedatabufferpos = responseop.userspacedatabuffer;
        u64 total_buffer_size_tally = 0;

        retval = read_block(entire_start, entire_length, userspacedatabufferpos);
        if (retval != 0)
          {
            retval = Ret::r(-EINVAL, "Error from storage.read_block, error: %d", retval);
            responseop.error = retval;
            goto error;
          }

        total_buffer_size_tally += entire_length;

        responseop.header.size = total_buffer_size_tally;
        responseop.packet.read_response.response_total_length_of_all_segment_requests = total_buffer_size_tally;

        error:

        retval = safe_ioctl(fd, IOCTL_DEVICE_OPERATION, &responseop);
        if (retval != 0)
          return Ret::r(retval, "ioctl call failed for device operation read response, err %d", retval);

        return Ret::r();
      }

    int respond_to_write_request(int fd, u32 handle_id, dblock_operation &requestop)
      {
        i32 error = 0;

        u32 operation_id = requestop.operation_id;
        u64 number_of_segments = requestop.packet.write_request.number_of_segments;

        dblock_operation &responseop = requestop;
        responseop.handle_id = handle_id;
        responseop.operation_id = operation_id;
        responseop.error = error;
        responseop.header.operation = DEVICE_OPERATION_WRITE_RESPONSE;
        responseop.header.size = 0;

        int ret = Ret::r();
        unsigned char *userspacedatabufferpos = requestop.userspacedatabuffer;
        u64 total_buffer_size_tally = 0;

        bool verify_start_first = true;
        u64 verify_start = 0;
        u64 entire_start = 0;
        u32 entire_length = 0;

        for (u32 lp = 0; lp < number_of_segments; lp++)
          {
            dblock_bio_segment_metadata *entry = &requestop.metadata[lp];
            u64 start = entry->start;
            u64 length = entry->length;

            if (verify_start_first == true)
              {
                verify_start_first = false;
                verify_start = start;
                entire_start = start;
              }
            else if (verify_start != start)
              return Ret::r(-EINVAL, "respond_to_write_request segments are not contiguous, expected start %lld got start %lld", verify_start, start);

            verify_start += length;
            entire_length += length;
          }

        total_buffer_size_tally += entire_length;

        int retval = write_block(entire_start, entire_length, userspacedatabufferpos);
        if (retval != 0)
          {
            retval = Ret::r(retval, "Error from storage.write_block, error: %d", retval);
            responseop.error = retval;

            goto error;
          }

        responseop.header.size = 0;
        responseop.packet.write_response.response_total_length_of_all_segment_requests_written = total_buffer_size_tally;

        error:

        retval = safe_ioctl(fd, IOCTL_DEVICE_OPERATION, &responseop);
        if (retval != 0)
          return Ret::r(retval, "ioctl call failed for device operation write response, err %d", retval);

        return Ret::r();
      }

    int run_block_for_request(int fd, dblock_operation &op)
      {
        while (true)
          {
            int r = block_for_request(fd, m_block_device_handle_id, op);

            if (r != 0)
              {
                if ((r == ENOENT) || (r == -ENOENT))
                  {
                    printf("got ENOENT on block device trying to block for request, failing out. error: %d\n", r);
                    return r;
                  }
                printf("Error from block_for_request, sleeping 1 second, error: %d\n", r);
                sleep(1);
              }
            else
              {
                break;
              }
          }
        return Ret::r();
      }

    int run(void)
      {
        int fdctl;
        string control_device_name = TXT_ZOSBD2_CONTROL_DEVICE_NAME;
        string full_control_device_name = "/dev/" + control_device_name;
        int retval = open_bd(full_control_device_name, fdctl);
        if (retval != 0)
          return retval;
        shared_ptr<int> x(NULL, [&](int*)
          { close(fdctl);});

        string device_name = TXT_DEVICE_NAME;
        retval = create_block_device(fdctl, device_name, 4096, 1048576, 30, m_block_device_handle_id);
        if (retval != 0)
          return retval;

        string full_device_name = "/dev/" + device_name + "-ctl";
        int fd;
        retval = open_bd(full_device_name, fd);
        if (retval != 0)
          return Ret::r(retval, "Error opening block device: %s, handle id: %d, error: %s", full_device_name.c_str(), m_block_device_handle_id, retval);
        shared_ptr<int> x2(NULL, [&](int*)
          { close(fd);});

        u32 alloc_size = sizeof(dblock_operation) + MAX_BIO_SEGMENTS_BUFFER_SIZE_PER_REQUEST;

        void *buffer = malloc(alloc_size);
        if (buffer == NULL)
          return Ret::r(-ENOMEM, "Unable to allocate memory for dblock_operation: %d", ENOMEM);

        dblock_operation &op = *((dblock_operation*)buffer);

        retval = run_block_for_request(fd, op);
        if (retval != 0)
          return Ret::r(EINVAL, "permanent failure from block_for_request, bailing out. error: %d", retval);

        while (true)
          {
            retval = Ret::r();
            switch (op.header.operation)
              {
              case DEVICE_OPERATION_KERNEL_BLOCK_FOR_REQUEST:
                {
                  retval = run_block_for_request(fd, op);
                  break;
                }
              case DEVICE_OPERATION_KERNEL_READ_REQUEST:
                {
                  retval = respond_to_read_request(fd, m_block_device_handle_id, op);
                  break;
                }
              case DEVICE_OPERATION_KERNEL_WRITE_REQUEST:
                {
                  retval = respond_to_write_request(fd, m_block_device_handle_id, op);
                  break;
                }
              case DEVICE_OPERATION_KERNEL_USERSPACE_EXIT:
                {
                  printf("got request from kernel to exit. exiting cleanly.\n");
                  return Ret::r();
                }
              default:
                {
                  printf("Unsupported request from kernel module: %d\n", op.header.operation);
                  retval = Ret::r(-EINVAL, "invalid request, blocking for another request.");
                  break;
                }
              }

            if (retval != 0)
              {
                printf("error from block_for_request call, sleeping and blocking for another request: %d\n", retval);
                retval = run_block_for_request(fd, op);
                if (retval != 0)
                  {
                    return Ret::r(-EINVAL, "permanent failure from block_for_request, bailing out. error: %d", retval);
                  }
              }
          }
      }

    int go(int num, char *opts[])
      {
        if (num > 1)
          {
            if (strcmp(opts[1], "-d") == 0)
              return destroy_block_device();
          }
        return run();
      }
  };

int main(int num, char *opts[])
  {
    libdblock bd;
    int r = bd.go(num, opts);
    if (r != 0)
      printf("error: %d\n", r);
    return r;
  }
