all: information

information: information.c
		gcc -o information information.c -lpcap -g -fsanitize=address

clean:
		rm -f information
