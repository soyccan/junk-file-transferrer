#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "master_dev.h"

#define PAGE_SIZE 4096
#define BUF_SIZE 4096
// TODO check correctness whether BUF_SIZE != 4096
// (buffer size in master device)

#define LOG(msg, ...) \
    fprintf(stderr, "\e[31mmaster: \e[0m" msg "\n", ##__VA_ARGS__)

static size_t get_filesize(const char* filename)
{
    struct stat st;
    stat(filename, &st);
    return st.st_size;
}

static void usage()
{
    fprintf(stderr, "[Usage] ./master N file1 file2 ... fileN fcntl/mmap\n");
    exit(1);
}

int main(int argc, char* argv[])
{
    char buf[BUF_SIZE];
    char* method = NULL;
    int num_file = 0;
    int ret = -1;
    int dev_fd = -1;
    char* mmdev = NULL;  // memory-mapped device

    if (argc <= 1)
        usage();
    num_file = atoi(argv[1]);
    if (argc != num_file + 3)
        usage();
    method = argv[num_file + 2];

    dev_fd = open("/dev/master_dev", O_RDWR);
    if (dev_fd < 0) {
        perror("failed to open /dev/master_dev");
        return dev_fd;
    }

    mmdev =
        mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, dev_fd, 0);
    if (mmdev == MAP_FAILED) {
        perror("mapping dev error");
        return 1;
    }
    LOG("mmap mmdev=0x%lx", mmdev);
    ioctl(dev_fd, MASTER_IOCTL_GET_PHYS, mmdev);

    LOG("wait for master device to accept connection");
    if ((ret = ioctl(dev_fd, MASTER_IOCTL_ACCEPT_CONN)) < 0) {
        perror("ioctl master device connection error");
        return ret;
    }
    LOG("master device connected");

    double total_times = 0;
    size_t total_sizes = 0;
    for (int i = 0; i < num_file; i++) {
        char* filename = argv[i + 2];
        int fd = open(filename, O_RDONLY);
        if (fd < 0) {
            perror("failed to open input file");
            return fd;
        }
        size_t filesize = get_filesize(filename);
        LOG("file=%s filesize=%zu", filename, filesize);

        struct timeval start;
        struct timeval end;
        gettimeofday(&start, NULL);

        if (method[0] == 'f') {  // fcntl : read()/write()
            // tell device the file size we're going to write
            assert(write(dev_fd, &filesize, 8) == 8);

            size_t count = filesize;
            while (count > 0) {
                size_t to_write = count;
                if (to_write > BUF_SIZE)
                    to_write = BUF_SIZE;
                assert(read(fd, buf, to_write) == to_write);
                assert(write(dev_fd, buf, to_write) == to_write);
                count -= to_write;
            }

        } else if (method[0] == 'm') {  // mmap
            // tell device the file size we're going to write
            memcpy(mmdev, &filesize, 8);
            if (ioctl(dev_fd, MASTER_IOCTL_FLUSH, 8) < 0) {
                perror("ioctl master device flush failed");
                return 1;
            }

            size_t count = filesize;
            while (count > 0) {
                size_t to_write = count;
                if (to_write > BUF_SIZE)
                    to_write = BUF_SIZE;
                assert(read(fd, buf, to_write) == to_write);

                memcpy(mmdev, buf, to_write);
                if (ioctl(dev_fd, MASTER_IOCTL_FLUSH, to_write) < 0) {
                    perror("ioctl master device flush failed");
                    return 1;
                }
                count -= to_write;
            }
        } else {
            usage();
        }
        gettimeofday(&end, NULL);
        double trans_time =
            (end.tv_sec - start.tv_sec) * 1000 +
            (end.tv_usec - start.tv_usec) * 0.001;  // millisecond
        total_times += trans_time;
        total_sizes += filesize;
        close(fd);
        LOG("time used: %lf ms; size: %zu; file: %s", trans_time, filesize,
            filename);
    }

    printf("Overall transmission time: %lf ms; Transmitted Size: %zu bytes\n",
           total_times, total_sizes);

    if ((ret = ioctl(dev_fd, MASTER_IOCTL_CLOSE_CONN)) < 0) {
        // end sending data, close the connection
        perror("ioclt master device close connection error");
        return ret;
    }

    if (munmap(mmdev, PAGE_SIZE) < 0) {
        perror("munmap failed");
    }
    mmdev = NULL;

    close(dev_fd);

    return 0;
}
