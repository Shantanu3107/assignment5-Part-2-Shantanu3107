CC ?= $(CROSS_COMPILE)gcc
CFLAGS := -Wall -Wextra -Werror -g
TARGET := aesdsocket
SRCDIR := .


.PHONY: all clean default


default: all


all: $(TARGET)


$(TARGET): aesdsocket.c
	$(CC) $(CFLAGS) -o $@ aesdsocket.c


clean:
	rm -f $(TARGET)
