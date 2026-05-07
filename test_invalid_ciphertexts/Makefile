CC = gcc

CFLAGS = -std=c11 \
          -Wall \
          -Wextra \
          -Wpedantic \
          -O0 \
          -g \
          -fsanitize=address \
          -I../userspace

TARGET = test_invalid_ciphertexts

SRC = \
	test.c \
	../userspace/keccak1600.c \
	../userspace/math_operations.c \
	../userspace/ml_kem.c \
	../userspace/ml_kem_create_keys.c \
	../userspace/ml_kem_decrypt.c \
	../userspace/ml_kem_encaps.c \
	../userspace/ml_kem_ntt_main.c \
	../userspace/ml_kem_pool.c \
	../userspace/ml_kem_sha3.c \
	../userspace/ml_kem_shake.c

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
