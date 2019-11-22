all: hello
CC= gcc -Wall
OBJS = test.o
hello: $(OBJS)
	$(CC) $(OBJS) -o hello
clean:
	rm -rf hello *.o
