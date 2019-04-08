
CFLAGS :=	-pipe \
		-Wall -Werror -O2 \
		-I/usr/include/x86_64-linux-gnu/

#KDIR := /lib/modules/$(shell uname -r)/source
#CPPFLAGS := -I $(KDIR)/tools/lib -I /usr/include/x86_64-linux-gnu/
#LDFLAGS := -L $(KDIR)/tools/lib/bpf

LDLIBS := -lelf -lm
BIN    := knodoh.o nodoh nodoh.o

all: $(BIN)

nodoh.o: nodoh.c common.h
	cc $(CFLAGS) -c nodoh.c -o nodoh.o

nodoh: nodoh.o /usr/lib/x86_64-linux-gnu/libbpf.a

knodoh.o: knodoh.c common.h
	clang $(CFLAGS) -target bpf -c $< -o $@

clean::
	$(RM) $(BIN)
