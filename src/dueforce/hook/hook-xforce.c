#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <unistd.h>
#include <string.h>
#include <malloc.h>
#include <fcntl.h>
#include <stdarg.h>


static void __hook_init(void) __attribute__((constructor));

static int (*real_open)(const char*, int, ...);

static FILE* (*real_fopen)(const char*, const char*);
static int (*real_fclose)(FILE*);

static void* (*real_calloc)(size_t, size_t);
static void* (*real_malloc)(size_t);
static void* (*real_memcpy)(void*, const void*, size_t);
static void (*real_free)(void*);

static int (*real_puts)(const char*);

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


void* calloc (size_t num, size_t size) {

  static int initializing = 0;

  if (!real_calloc) real_calloc = dlsym(RTLD_NEXT, "calloc");
printf("calloc: %x\n", size);
  void *memory = real_calloc(num, size);

  for (size_t i = 0; i < size / addr_size; i++) {

    target_ulong val = fill_value();
    memcpy((void*)(intptr_t)(memory + i * addr_size), &val, addr_size);

  }


//printf("calloc2: %x %x %lx\n", num, size, memory);
  return memory;

}


void* malloc(size_t size) {

  static int initializing = 0;

  if (!real_malloc) real_malloc = dlsym(RTLD_NEXT, "malloc");

  void *memory = real_malloc(size);
  for (size_t i = 0; i < size / addr_size; i++) {

    target_ulong val = fill_value();
    memcpy((void*)(intptr_t)(memory + i * addr_size), &val, addr_size);

  }

  return memory;

}


void free(void *ptr) {
  if (!real_free) real_free = dlsym(RTLD_NEXT, "free");
  if (ptr >= page_size) real_free(ptr);

}

/*
void* memcpy(void *dest, const void *src, size_t size) {

  if (!real_memcpy) real_memcpy = dlsym(RTLD_NEXT, "memcpy");
  printf("my memcpy: %p %p %d\n", dest, src, size);
  real_memcpy(dest, src, size);

}
*/

int puts(const char* str) {

  if (!real_puts) real_puts = dlsym(RTLD_NEXT, "puts");
  //printf("my puts\n");
//  printf("my puts: %p\n", str);
  real_puts(str);

}
