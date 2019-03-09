# snetscan
Simple Network Scanner -- Print hosts connected to the network

## How it works
The scanner uses **libnet** to send ARP requests for every possible host on the network, while listening for ARP replies with **libpcap**; we understand that those host for which the scanner receives an ARP reply is connected to the network.

* **libnet** code can be found on scan.c
* **libpcap** code can be found on cap.c

Once we have the MAC address of the host which replied our ARP request, the scanner parses a csv file from the IEEE webpage(see Makefile), and
gets the manufacturer/vendor for the specific network hardware it observes from the MAC.

__NOTE:__ *Root permissions are needed in order to use the scanner*

## Dependencies

Primarily, you will need to install **wget** to download the csv and both **libnet** and **libpcap** to compile the scanner.

* **Debian based**:

```
sudo apt-get install wget
sudo apt-get install libnet-dev
sudo apt-get install libpcap-dev
```

* **Fedora**:

```
sudo yum install wget
sudo yum install libnet-devel
sudo yum install libpcap-devel
```

* **Arch Linux**:

```
sudo pacman -S wget
sudo pacman -S libnet
sudo pacman -S libpcap
```

__NOTE:__ You can install *snetscan* directly via AUR:

```
yaourt -S snetscan-git
```

## Usage
Compile the project on Linux with **make**. You need to tell the scanner the interface/device to use in the scan. You can check possible interfaces/devices by running the scanner with no arguments:



    [github@drnoob snetscan]$ ./snetscan
    WARNING: DEVICE option is mandatory
    Available devices are:
       * enp3s0
       * lo
    Usage: ./snetscan --dev DEVICE [--help]
       Options:
       --dev    Set network interface
       --help   Print this help and exit

Then, specify the interface with *--dev*    

    [github@drnoob snetscan]$ sudo ./snetscan --dev enp3s0
    Using interface: 'enp3s0'
    Scanning from 192.168.1.1 to 192.168.1.254
    Waiting for requests...

    IP Addess          MAC Address       
    192.168.1.1        24:76:7D:XX:XX:XX (Cisco SPVTG)
    192.168.1.10       30:B5:C2:XX:XX:XX (TP-LINK TECHNOLOGIES CO.,LTD.)
    192.168.1.49       04:D6:AA:XX:XX:XX (SAMSUNG ELECTRO-MECHANICS(THAILAND))
    192.168.1.100      F8:32:E4:XX:XX:XX (ASUSTek COMPUTER INC.)
    192.168.1.101      90:B1:1C:XX:XX:XX (Dell Inc.)
