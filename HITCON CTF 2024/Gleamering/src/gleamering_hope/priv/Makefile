CC=gcc
CFLAGS=-I. -fpic -shared -fno-stack-protector
DEPS = 
OBJ = gleamering_hope_ffi.o
LIBS =

all: gleamering_hope_ffi.so

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

gleamering_hope_ffi.so: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS) -s

.PHONY: clean

clean:
	rm -f *.o gleamering_hope_ffi.so
