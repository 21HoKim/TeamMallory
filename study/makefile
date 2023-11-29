all: information sendSSID

information: information.c
		gcc -o information information.c -lpcap -g -fsanitize=address

sendSSID: sendSSID.c
		gcc -o sendSSID sendSSID.c -lpcap -g -fsanitize=address
clean:
		rm -f information
		rm -f sendSSID
