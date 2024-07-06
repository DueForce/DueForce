#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
//#include <unistd.h>
#include <string.h>
#include <malloc.h>
#include <fcntl.h>
#include <stdarg.h>
#include <setjmp.h>


static void __hook_init(void) __attribute__((constructor));
static void __hook_fini(void) __attribute__((destructor));

static int (*real_open)(const char*, int, ...);

static FILE* (*real_fopen)(const char*, const char*);
static int (*real_fclose)(FILE*);

static void* (*real_calloc)(size_t, size_t);
static void* (*real_malloc)(size_t);
static void* (*real_memcpy)(void*, const void*, size_t);
static void (*real_free)(void*);

static int (*real_puts)(const char*);

static void (*real__ZNSsC1EPKcRKSaIcE)(void*, void*, void*);
static void (*real__ZNSsC1ERKSs)(void*, void*);
static void (*real__ZNSs6appendERKSs)(void*, void*);
static void* (*real_gethostbyname)(const char *name);

static int (*real_pthread_create)(void*, const void*, void*, void*);

static void (*real_exit)(int);


size_t addr_size = 8;
size_t page_size = 0x10000;
typedef unsigned long target_ulong;


target_ulong fill_value(void) {

  return 0;

}


int open(const char *filename, int flags, ...) {

  if (!real_open) real_open = dlsym(RTLD_NEXT, "open");

  int fd = real_open(filename, flags);

  if (fd == -1) {

    char padding[128];

    if (flags == O_RDONLY || flags == O_RDWR) sprintf(padding, "%s/hook/rpadding", getenv("ROOT"));
    else if (flags == O_WRONLY) sprintf(padding, "%s/hook/wpadding", getenv("ROOT"));  

    fd = real_open(padding, flags);

  }

  return fd;

}


FILE* fopen(const char *filename, const char *mode) {

  if (!real_fopen) real_fopen = dlsym(RTLD_NEXT, "fopen");

  FILE *file = real_fopen(filename, mode);

  if (!file) {

    char padding[128];

    if (strchr(mode, 'r') != NULL) sprintf(padding, "%s/hook/rpadding", getenv("ROOT"));  
    else if (strchr(mode, 'w') != NULL || strchr(mode, 'a') != NULL) sprintf(padding, "%s/hook/wpadding", getenv("ROOT"));  

    file = real_fopen(padding, mode);

  }

  return file;

}


int fclose(FILE *file) {

  if (!real_fclose) real_fclose = dlsym(RTLD_NEXT, "fclose");;

  if (file) return real_fclose(file);
  else return 0;

}


/*
TODO: handle calloc
void* calloc (size_t num, size_t size) {

  static int initializing = 0;

  if (!real_calloc) real_calloc = dlsym(RTLD_NEXT, "calloc");

  void *memory = real_calloc(num, size);

  for (size_t i = 0; i < size / addr_size; i++) {

    target_ulong val = fill_value();
    memcpy((void*)(intptr_t)(memory + i * addr_size), &val, addr_size);

  }

  return memory;

}
*/


void* malloc(size_t size) {

  if (!real_malloc) real_malloc = dlsym(RTLD_NEXT, "malloc");

  void *memory = 0x0;

  if (size < 0x10000 /*1 << 27*/) {

    if (size > 0x10000) size = 0x10000;
    memory = real_malloc(size);

    for (size_t i = 0; i < size / addr_size; i++) {

      target_ulong val = fill_value();
      memcpy((void*)(memory + i * addr_size), &val, addr_size);

    }

  }

  return memory;

}


/*
void exit(int arg0) {

  if (!real_exit) real_exit = dlsym(RTLD_NEXT, "exit");
  if (arg0 == 0) real_exit(arg0);

}
*/

void free(void *ptr) {

  if (!real_free) real_free = dlsym(RTLD_NEXT, "free");
  if (ptr >= page_size) real_free(ptr);

}


void* memcpy(void *dest, const void *src, size_t size) {

  if (!real_memcpy) real_memcpy = dlsym(RTLD_NEXT, "memcpy");

  real_memcpy(dest, src, size);

}


int puts(const char* str) {

  if (!real_puts) real_puts = dlsym(RTLD_NEXT, "puts");

  real_puts(str);

}


void _ZNSsC1EPKcRKSaIcE(void *arg0, void *arg1, void *arg2) {

  if (!real__ZNSsC1EPKcRKSaIcE) 
    real__ZNSsC1EPKcRKSaIcE = dlsym(RTLD_NEXT, "_ZNSsC1EPKcRKSaIcE");

  if (arg1 == NULL) arg1 = 0x0;

  real__ZNSsC1EPKcRKSaIcE(arg0, arg1, arg2);

}


void _ZNSsC1ERKSs(void *arg0, void *arg1) {

  if (!real__ZNSsC1ERKSs)
    real__ZNSsC1ERKSs = dlsym(RTLD_NEXT, "_ZNSsC1ERKSs");

  if (arg1 == NULL/* || arg1 == 0x638ca0*/) arg1 = 0x0;

  real__ZNSsC1ERKSs(arg0, arg1);

}


void _ZNSs6appendERKSs(void *arg0, void *arg1) {

  if (!real__ZNSs6appendERKSs)
    real__ZNSs6appendERKSs = dlsym(RTLD_NEXT, "_ZNSs6appendERKSs");

  if (arg1 == NULL/* || arg1 == 0x638ca0 || arg1 == 0x638ca8*/) arg1 = 0x0;

  real__ZNSs6appendERKSs(arg0, arg1);

}


void* gethostbyname(const char *arg0) {

  if (!real_gethostbyname) real_gethostbyname = dlsym(RTLD_NEXT, "gethostbyname");

  if (arg0 == NULL/* || arg0 == 0x8000000000000010*/) arg0 = 0x0;

  return real_gethostbyname(arg0);

}


/*
int kill(int arg0, int arg1) {

  if (!real_kill) real_kill = dlsym(RTLD_NEXT, "kill");

  //return real_kill(arg0, arg1);

}


int fork(void) {

  if (!real_fork) real_fork = dlsym(RTLD_NEXT, "fork");

  //return real_fork();
  return 0;

}
*/


int pthread_create(void *thread, const void *attr, void *routine, void **arg) {


  if (!real_pthread_create) real_pthread_create = dlsym(RTLD_NEXT, "pthread_create");

  __asm__("leave;\
           mov %0, %%rdi;\
           mov %1, %%rsi;\
           push %2;\
           ret;" : : "g"(arg[0]), "g"(arg[1]), "r"(routine));

  //return real_pthread_create(thread, attr, routine, arg);
  return 0;

}


void __isoc99_scanf(void *arg0, void *arg1) {
}


void __isoc99_fscanf(void *arg0, void *arg1, void *arg2) {
}


void longjmp(jmp_buf arg0, int arg1) {
  exit(0);
}


void siglongjmp(sigjmp_buf arg0, int arg1) {
  exit(0);
}


void __hook_init(void) {



}


void __hook_fini(void) {



}

int read(int fd, void* buf, size_t size) {
  return size;
}
