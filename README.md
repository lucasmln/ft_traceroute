# ft_traceroute
traceroute  tracks the route packets taken from an IP network on their way to a given host. It utilizes the IP protocol's time to live (TTL) field and attempts to elicit
an ICMP TIME_EXCEEDED response from each gateway along the path to the host.  
Probe packets are udp datagrams with so-called "unlikely" destination ports
The "unlikely" port of the first probe is 33434, then for each next probe it is incremented by  one.  
Since the ports are expected to be unused, the destination host normally returns "icmp unreach port" as a final response.
(Nobody knows what happens when some application listens for such ports, though).

## Usage :
```
Make && sudo ./ft_traceroute [-I] [-f first_ttl] [-m max_ttl] [-p port] [-q nqueries] [-w waittime] [-z sendwait] destination [packet_len]
```
## Options :

* `[-h --help]` Display usage and options
* `[-I --icmp]` Use protocol ICMP to send packet
* `[-f first_ttl]` Set the first ttl (default 1)
* `[-m max_ttl]` Set the maximum ttl (default 30)
* `[-n]` Do not try to map IP addresses to host names when displaying them
* `[-p port]`	For UDP tracing, specifies the destination port base traceroute will use (the destination port number will be incremented by each probe)
				For ICMP tracing, specifies the initial ICMP sequence value (incremented by each probe too)
* `[-q nqueries]` Set the number of probe packet per hop (default is 3)
* `[-w waittime]` Set the receve timeout value in sec
* `[-z sendwait]` Set the time to wait between probes. if the value is more than 10, then it's in ms, else it's in sec
* `[packet_len]` Set the size of the packet (default 60)
