# ft_traceroute

## Usage :
```
Make && sudo ./ft_traceroute [-I] [-f first_ttl] [-m max_ttl] [-p port] [-q nqueries] [-w waittime] [-z sendwait] destination [packet_len]
```
## Options :

* `[-I]` Use protocol ICMP to send packet
* `[-f first_ttl]` Set the first ttl (default 1)
* `[-m max_ttl]` Set the maximum ttl (default 30)
* `[-p port]`	For UDP tracing, specifies the destination port base traceroute will use (the destination port number will be incremented by each probe)
				For ICMP tracing, specifies the initial ICMP sequence value (incremented by each probe too)
* `[-q nqueries]` Set the number of probe packet per hop (default is 3)
* `[-w waittime]` Set the receve timeout value in sec
* `[-z sendwait]` Set the time to wait between probes. if the value is more than 10, then it's in ms, else it's in sec
* `[packet_len]` Set the size of the packet (default 60)
