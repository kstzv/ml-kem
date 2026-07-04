CC ?= gcc

CFLAGS = -O3 -Wall -Wextra -std=c11 \
		 -DUSERSPACE \
		 -I../../userspace \
         -I../../../src

LDFLAGS =
LDLIBS = ../libmlkem.a

TEST = test.c

TARGET = test

all:
	$(CC) $(CFLAGS) $(TEST) $(LDFLAGS) -o $(TARGET) $(LDLIBS)

clean:
	rm -f $(TARGET)
