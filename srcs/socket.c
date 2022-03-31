#include "../inc/ft_traceroute.h"

void	create_socket()
{
	struct timeval	timeout;
	int		on = 1;

	if ((g_data.raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
		error_socket("ft_traceroute: error: create socket RAW failed");
	if ((g_data.icmp_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0)
		error_socket("ft_traceroute: error: create socket ICMP failed");
	timeout.tv_sec = 1;
	timeout.tv_usec = 0.1;
	if (setsockopt(g_data.raw_sock, IPPROTO_IP, IP_HDRINCL, (const char *)&on, sizeof(on)) < 0)
		error_socket("ft_traceroute: error: set IP_HDRINCL option");
	if (setsockopt(g_data.icmp_sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0)
		error_socket("ft_traceroute: error: set timeout option\n");
	on = IP_PMTUDISC_DO;
	if (setsockopt(g_data.icmp_sock, SOL_IP, IP_RECVTTL, &on, sizeof(on)) < 0)
		error_socket("ft_traceroute: error: set IP_RECVTTL failed\n");
	timeout.tv_usec = 1;
	timeout.tv_sec = 0;
	if (setsockopt(g_data.icmp_sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0)
	{
		fprintf(stderr, "Setting socket options to timeout failed! %m\n");
		exit(1);
	}
}

void	error_socket(const char *error)
{
	printf("%s\n", error);
	free_traceroute();
	exit(1);
}

void	dns_lookup(const char *dest)
{
	struct addrinfo		hint;
	struct addrinfo		*res = NULL;
	char				*tmp;

	ft_bzero(&hint, sizeof(hint));
	hint.ai_family = AF_INET;
	hint.ai_socktype = SOCK_STREAM;
	if (getaddrinfo(dest, NULL, &hint, &res) != 0)
	{
		printf("%s: Name or service not known\n", dest);
		exit(1);
	}
	ft_memcpy(&g_data.addr, res->ai_addr, sizeof(res->ai_addr));
	tmp = inet_ntoa(g_data.addr.sin_addr);
	g_data.addr_ip = ft_strdup(tmp);
	freeaddrinfo(res);
}

