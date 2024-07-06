CC = gcc
CFLAGS = -g -fPIC -std=c99
RM = rm -f

all: libhook-determ.so libhook-random.so libhook-xforce.so
clean:
	$(RM) *.o *.so

libhook-determ.so: hook-determ.o
	$(LINK.c) -shared $< -o $@ -ldl

libhook-random.so: hook-random.o
	$(LINK.c) -shared $< -o $@ -ldl

libhook-xforce.so: hook-xforce.o
	$(LINK.c) -shared $< -o $@ -ldl

hook-determ.o: hook-determ.c

hook-random.o: hook-random.c

hook-xforce.o: hook-xforce.c
