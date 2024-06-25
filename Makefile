TARGET = ahf-simple
CC = clang
CFLAGS = -I. -Wall -Werror -Wno-parentheses
LDFLAGS = -framework Hypervisor
SRCS = $(shell ls *.c)
OBJS = $(patsubst %.c,%.o,$(SRCS))
INCS = $(shell ls *.h)

.c.o:
	$(CC) $(CFLAGS) -c $<

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $@ $(LDFLAGS)
	codesign -s - --entitlements $(TARGET).entitlements --force $@

-include *.d

clean:
	rm -f $(TARGET) *.o
