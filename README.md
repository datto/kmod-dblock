# kmod-dblock

kmod-dblock is a kernel module that allows you to implement the backing data source for a block device in userspace.

# building

to build the kernel module you must have the kernel headers for your running kernel installed.

Fedora/CentOS/RHEL:

```sudo yum -y install kernel-devel-$(uname -r)```

Debian/Ubuntu:

```sudo apt install linux-headers-$(uname -r)```

Raspberry Pi OS:

```sudo apt install raspberrypi-kernel-headers```

once the headers are installed, you can build the kernel module

```
make
sudo insmod dblock.ko
```

to build the sample ramdisk userspace implementation

```
cd sample_ramdisk
make
```


# sample program

if you run the resulting binary from the build...

```
sudo ./dblock_sample_ramdisk
```
the process will create a block device called `/dev/dblockramdisk` and the process will block handling requests to that block device.

in another terminal you can create a file system on the block device.

```
sudo mkfs.ext4 /dev/dblockramdisk
```
then you can mount it

```
mkdir mount
sudo mount /dev/dblockramdisk mount
```

then you can `cd mount` to use the ramdisk created by dblock.ko

to cleanly exit the block device

unmount the file system
```
umount mount
```

to exit the userspace process cleanly and destroy the block device, run the userspace program with the -d parameter.

```
sudo ./dblock_sample_ramdisk -d
```

that will destroy the block device and the dblock_sample_ramdisk process in the first terminal will exit.



# how it works

the kernel module once loaded, creates a misc device called `/dev/dblockctl`.
this device is how userspace applications can make requests to the dblock.ko kernel module to create and destroy block devices. the kernel module supports multiple concurrent block devices.

when the userspace program starts, it sends an ioctl to the control device with information about the size and shape of block device to make.
the kernel module makes the block device in the kernel, and creates a queue in its memory to hold requests.

the the userspace program makes an ioctl to the newly created block device, and it blocks waiting for something to appear on the queue.
when a request comes in for the block device, the information about the request (is it a read or a write, and if it's a write, what data needs to be written) is returned to the userspace application that was blocking on the ioctl call.

the userspace application then handles the request either collecting the data for read requests or storing the data for write requests, and then calls the ioctl again with the results of the request that was handled.

the kernel module then sends the results sent from userspace to the kernel for the block device that the initial request came from and then blocks again waiting for something else to do.

this cycle continues until an ioctl is make to the control device to destroy the block device.

when a block device is destroyed, the kernel module sends a special response to the userspace blocking ioctl saying basically there are no more requests coming and the userspace program should not call back.


# more details

it builds and runs on x86 and ARM (both 32-bit and 64-bit).

it runs on Fedora 33, Ubuntu 18.04, Ubuntu 20.04, and Raspberry Pi OS.

I've tested it with the 4.15 kernel and the 5.8 kernel and the 5.10 kernel.

because of the way the sample program is written it can only handle one request at a time.
all requests from the block device are handled roughly in the order in which they came in.



