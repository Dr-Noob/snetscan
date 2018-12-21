scan: Makefile scan.c cap.c cap.h
	gcc scan.c cap.c -g -lnet -lpcap -pthread -o scan

clean:
	rm scan

run: scan
	sudo ./scan
