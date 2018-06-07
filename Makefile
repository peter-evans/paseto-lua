
LUADIR ?= ../lua
LUA ?= $(LUADIR)/bin/lua
LUAINC ?= $(LUADIR)/include 

#-----------------------------------------------------

CC ?= gcc

INCFLAGS= -I$(LUAINC)

CFLAGS= -Os -fPIC $(INCFLAGS)
LDFLAGS= -shared -lsodium

luasodium.so:  csrc/*.c
	$(CC) -c $(CFLAGS) csrc/*.c
	$(CC) $(LDFLAGS) -o luasodium.so luasodium.o

clean:
	rm -f *.o *.a *.so

.PHONY: clean
