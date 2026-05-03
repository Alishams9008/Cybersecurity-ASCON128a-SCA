#include <sys/stat.h>
#include <stdint.h>

/* Minimal syscall stubs for bare-metal ARM Cortex-M3.
 * These satisfy the linker when no OS is present.
 * Rainbow's emulator never actually calls these —
 * they exist only to produce a valid ELF. */

void _exit(int status) { while(1); }
int  _kill(int pid, int sig) { return -1; }
int  _getpid(void) { return 1; }
int  _write(int fd, char *buf, int len) { return len; }
int  _read(int fd, char *buf, int len) { return 0; }
int  _close(int fd) { return -1; }
int  _fstat(int fd, struct stat *st) { st->st_mode = S_IFCHR; return 0; }
int  _isatty(int fd) { return 1; }
int  _lseek(int fd, int offset, int whence) { return 0; }

/* Heap stub — gives Rainbow a small heap to work with */
static uint8_t heap[4096];
static uint8_t *heap_ptr = heap;

void *_sbrk(int incr)
{
    uint8_t *prev = heap_ptr;
    heap_ptr += incr;
    return (void *)prev;
}