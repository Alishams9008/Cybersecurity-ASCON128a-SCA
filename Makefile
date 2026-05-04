CC = gcc
ARM_CC = arm-none-eabi-gcc
ARM_CFLAGS = -mcpu=cortex-m3 -mthumb -O0 -fno-inline -nostartfiles
CFLAGS = -O0
SRCS = src/ascon128.c src/main.c
OBJS = $(SRCS:.c=.o)
TARGET = ascon_test
ARM_ELF = bin/ascon128.elf

all: $(TARGET) $(ARM_ELF)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) $(SRCS) -o $(TARGET)

$(ARM_ELF): src/ascon128.c src/syscalls.c
	@mkdir -p bin
	$(ARM_CC) $(ARM_CFLAGS) src/ascon128.c src/syscalls.c -o $(ARM_ELF)
	@echo "ARM ELF: OK"

run: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TARGET) $(ARM_ELF)

.PHONY: all run clean
