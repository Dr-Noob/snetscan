scan: Makefile scan.c cap.c cap.h printer.c printer.h macdb.csv
	gcc scan.c cap.c printer.c -g -lnet -lpcap -pthread -o scan

clean:
	rm scan

macdb.csv:
	wget http://standards-oui.ieee.org/oui/oui.csv
	cat oui.csv | cut -d',' -f2- > macdb.csv
	rm oui.csv

run: scan
	sudo ./scan
