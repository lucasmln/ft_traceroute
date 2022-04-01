#include "../inc/ft_traceroute.h"

void	print_traceroute_hdr(char *dst, char *dns_dst, int hops, long unsigned int pck_size)
{
	if (g_data.flags & FLAGS_I)
		pck_size = pck_size > sizeof(struct iphdr) + sizeof(struct icmphdr) ? pck_size : sizeof(struct iphdr) + sizeof(struct icmphdr);
	else
		pck_size = pck_size > sizeof(struct iphdr) + sizeof(struct udphdr) ? pck_size : sizeof(struct udphdr) + sizeof(struct iphdr);
	printf("ft_traceroute to %s (%s), %d hops max, %ld byte packets\n", dst, dns_dst, hops, pck_size);
}

void	print_usage()
{
	printf("Usage:\n");
	printf("\tft_traceroute: [ -hI ] [ -f first_ttl ] [ -m max_ttl ] [ -p port ] ");
	printf("[ -q nqueries ] [ -w waittime ] [ -z sendwait ] destination [ packet_len ]\n");
	printf("Options:\n");
	printf("\t-h --help\t\tDisplay usage\n");
	printf("\t-f first_ttl\t\tStart from the first_ttl hop (instead from 1)\n");
	printf("\t-I --icmp\t\tUse ICMP ECHO for tracerouting\n");
	printf("\t-m max_ttl\t\tSet the max number of hops (max TTL to be reached).\n\t\t\t\tDefault is 30\n");
	printf("\t-p port\t\t\tSet the destination port to use. It is either initial udp\n");
	printf("\t\t\t\tport value for %cdefault%c method(incremented by each probe,\n", '"', '"');
	printf("\t\t\t\tdefault is 33434), or initial seq for %cicmp%c (incremented as well,\n", '"', '"');
	printf("\t\t\t\tdefault from 1), or some constant destination port for other methods\n");
	printf("\t\t\t\t(with default of 80 for%ctcp%c 53 for %cudp%c, etc.)\n", '"', '"', '"', '"');
	printf("\t-w MAX\t\t\tWait for a probe no more than MAX\n");
	printf("\t-q nqueries\t\tSet the number of probes per each hop. Default is 3\n");
	printf("\t-z sendwait\t\tMinimal time interval between probes (default 0).\n");
	printf("\t\t\t\tIf the value is more than 10, then it specifies a number in ms,\n");
	printf("\t\t\t\telse it is a number in sec (float point values allowed)\n");
}

void	print_packet(int round, int ttl, struct timeval time, int code)
{
	double	time_value;
	char	*new_addr;
	char	*reverse_addr = NULL;
	static int	error = 0;

	if (!(g_data.flags & FLAGS_N))
		reverse_addr = reverse_dns_lookup(g_data.rcv);
	if (!reverse_addr)
		reverse_addr = ft_strdup(inet_ntoa(g_data.rcv.sin_addr));
	new_addr = ft_strdup(inet_ntoa(g_data.rcv.sin_addr));
	if (round == 0)
		printf("%d  ", ttl);
	else
		printf(" ");
	if (code == ERROR_CODE)
	{
		printf("*");
		error = 1;
	}
	else
	{
		time_value = (double)(((double)time.tv_sec * 1000) + ((double)time.tv_usec / 1000));
		if (g_data.last_ip == NULL || round == 0 || error == 1 || 
			ft_strncmp(g_data.last_ip, new_addr, ft_strlen(g_data.last_ip)) != 0)
			printf("%s (%s)  %.3lf ms", reverse_addr, new_addr, time_value);
		else
			printf(" %.3lf ms", time_value);
		error = 0;
	}
	if (round == 2)
		printf("\n");
	if (code != ERROR_CODE)
	{
		if (g_data.last_ip != NULL)
			free(g_data.last_ip);
		g_data.last_ip = ft_strdup(inet_ntoa(g_data.rcv.sin_addr));
	}
	free(new_addr);
	free(reverse_addr);
}

unsigned short	checksum(void *address, int len)
{
	unsigned short	*buff;
	unsigned long	sum;

	buff = (unsigned short *)address;
	sum = 0;
	while (len > 1)
	{
		sum += *buff;
		buff++;
		len -= sizeof(unsigned short);
	}
	if (len)
		sum += *(unsigned char *)buff;
	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	return ((unsigned short)~sum);
}
