snetscan: Makefile scan.c cap.c cap.h printer.c printer.h args.c args.h macdb.csv
	gcc scan.c cap.c printer.c args.c -g -lnet -lpcap -pthread -o snetscan

clean:
	rm snetscan

macdb.csv:
	wget http://standards-oui.ieee.org/oui/oui.csv
	cat oui.csv | cut -d',' -f2- > macdb.csv
	rm oui.csv

run: scan
	sudo ./snetscan
