CFLAGS=-g
.PHONY : clean

all: verify splitgmap

verify: verify.o
	gcc -o $@ $?

splitgmap: splitgmap.o
	gcc -o $@ $?

%.o: %.c
	gcc -c $(CFLAGS) -o $@ $<

clean:
	rm -f *.o
	rm *.png
