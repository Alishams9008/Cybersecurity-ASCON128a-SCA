CC = gcc
CFLAGS = -O0
SRCS = src/ascon128.c src/main.c
OBJS = $(SRCS:.c=.o)
TARGET = ascon_test

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) $(SRCS) -o $(TARGET)

run: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TARGET)

.PHONY: all run clean
