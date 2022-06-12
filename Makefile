SRC = main.c
OBJ = $(SRC:.c=.o)

all: $(OBJ)
	gcc -g $^ #-lseccomp

%.o: %.c
	gcc -g -c $<

clean:
	rm -rf a.out main.o
