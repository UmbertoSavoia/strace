SRC = main.c
OBJ = $(SRC:.c=.o)

all: $(OBJ)
	gcc $^ #-lseccomp

%.o: %.c
	gcc -c $<

clean:
	rm -rf a.out main.o
