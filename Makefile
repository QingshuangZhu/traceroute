CC=gcc
SRCS=$(wildcard *.c */*.c)
OBJS=$(patsubst %.c, %.o, $(SRCS))
CFLAG=-g
#NAME=$(wildcard *.c)
#TARGET=$(patsubst %.c, %, $(NAME))

TARGET=traceroute

$(TARGET):$(OBJS)
	$(CC) -o $@ $^ $(CFLAG)

%.o:%.c
	$(CC) -o $@ -c $< -g

clean:
	rm -rf $(TARGET) $(OBJS)