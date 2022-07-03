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
	@for i in 1 2 3 4 5; do \
  		gcc ./test/test$$i.c -o ./test/test$$i.64.out -pthread; \
  		gcc ./test/test$$i.c -m32 -o ./test/test$$i.32.out -pthread; \
  	done;

clean_test:
	$(RM) ./test/*.out

.PHONY: all clean fclean re test clean_test
