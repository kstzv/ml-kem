CC ?= gcc

CFLAGS = -std=c11 \
          -Wall \
          -Wextra \
          -Wpedantic \
          -O0 \
          -g \
          -fsanitize=address \
          -I../../src

TARGET = test

SRC = \
	test.c \
	../../src/keccak1600.c \
	../../src/ml_kem.c \
	../../src/ml_kem_create_keys.c \
	../../src/ml_kem_decrypt.c \
	../../src/ml_kem_encaps.c \
	../../src/ml_kem_ntt_main.c \
	../../src/ml_kem_pool.c \
	../../src/ml_kem_sha3.c \
	../../src/ml_kem_shake.c

OBJ = $(SRC:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

run: $(TARGET)
	./$(TARGET)

valgrind: $(TARGET)
	valgrind $(VALGRIND_FLAGS) ./$(TARGET)

clean:
	rm -f $(OBJ) $(TARGET)

rebuild: clean all

.PHONY: all run valgrind clean rebuild
