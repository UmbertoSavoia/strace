TARGET = ft_strace
CC = gcc
CFLAGS = -g #-Werror -Wall -Wextra
RM = rm -f

SRC = $(wildcard src/*.c)
OBJ = $(SRC:.c=.o)

all: $(OBJ)
	$(CC) $(CFLAGS) $^ -o $(TARGET)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	$(RM) $(OBJ)

fclean: clean
	$(RM) $(TARGET)

re: fclean all

test:
	$(CC) ./test/test1.c -o ./test/test1.out
	$(CC) ./test/test2.c -o ./test/test2.out
	$(CC) ./test/test3.c -o ./test/test3.out
	$(CC) ./test/test4.c -o ./test/test4.out
	$(CC) ./test/test5.c -o ./test/test5.out -lpthread

clean_test:
	$(RM) ./test/test1.out ./test/test2.out ./test/test3.out ./test/test4.out ./test/test5.out

.PHONY: all clean fclean re test clean_test
