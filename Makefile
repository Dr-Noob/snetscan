CXX=gcc
SANITY_FLAGS=-std=gnu99 -Wall -Wextra -Werror -fstack-protector-all -pedantic -Wno-unused -Wfloat-equal -Wshadow -Wpointer-arith -Wstrict-overflow=5 -Wformat=2

snetscan: Makefile scan.c cap.c cap.h printer.c printer.h args.c args.h macdb.csv
	$(CXX) scan.c cap.c printer.c args.c $(SANITY_FLAGS) -lnet -lpcap -pthread -o snetscan

clean:
	rm snetscan

macdb.csv:
	wget http://standards-oui.ieee.org/oui/oui.csv
	cat oui.csv | cut -d',' -f2- > macdb.csv
	rm oui.csv
