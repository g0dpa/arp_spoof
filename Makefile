all: arp_spoof

arp_spoof: main.o
	gcc -o arp_spoof main.o -lpcap

main.o: main.c
	gcc -c -o main.o main.c

clean:
	rm main.o
	rm arp_spoof
