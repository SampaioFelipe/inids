# INIDS

**Implementation of an Immune Network Intrusion Detection System (INIDS)**

## Usage

```shellscript
   sudo inids [-f filename | -e expression]
```

### Options

    -f: Activate the OFFLINE mode, which analyses a file in libpcap file format (.pcap) instead of the real-time network flow.
        You must pass the file path after the '-f' flag. 
   
    -e  Enables you to specify a BPF (Berkeley Packet Filter) expression to filter the packets.
        You must write the expression inside single quotes, like: " inids -e 'dst host 127.0.0.1'".
        See more [here](https://www.tcpdump.org/manpages/pcap-filter.7.html)  

## Examples
ONLINE MODE with Filter Expression

```
sudo inids -e 'src host 10.0.2.15'

```

OFFLINE MODE with Filter Expression
```
sudo inids -f /home/smallFlows.pcap -e 'src host 10.0.2.15'

```

## Protocols Supported


