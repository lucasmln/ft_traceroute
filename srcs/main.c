#include "../inc/ft_traceroute.h"

void	print_usage()
{
	printf("Usage: ft_traceroute: destination\n");
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

void	dns_lookup(const char *dest)
{
	struct addrinfo		hint;
	struct addrinfo		*res = NULL;
	char				tmp[INET_ADDRSTRLEN];

	ft_bzero(&hint, sizeof(hint));
	hint.ai_family = AF_INET;
	hint.ai_socktype = SOCK_STREAM;
	if (getaddrinfo(dest, NULL, &hint, &res) != 0)
	{
		printf("%s: Name or service not known\n", dest);
		exit(1);
	}
	ft_memcpy(&g_data.addr, res->ai_addr, sizeof(res->ai_addr));
	inet_ntop(AF_INET, &g_data.addr.sin_addr, tmp, sizeof(tmp));
	g_data.addr_ip = ft_strdup(tmp);
	printf("addr : %s\n", g_data.addr_ip);
	//freeaddrinfo(res);
}

void	free_traceroute()
{
	if (g_data.addr_ip)
		free(g_data.addr_ip);
	close(g_data.icmp_sock);
	close(g_data.raw_sock);
}

void	error_socket(const char *error)
{
	printf("%s\n", error);
	free_traceroute();
	exit(1);
}

void	create_socket()
{
	struct timeval	timeout;
	int		on = 1;

	if ((g_data.icmp_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0)
		error_socket("ft_traceroute: error: create socket ICMP failed");
	if ((g_data.raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
		error_socket("ft_traceroute: error: create socket RAW failed");
	timeout.tv_sec = 1;
	timeout.tv_usec = 0;
	if (setsockopt(g_data.raw_sock, IPPROTO_IP, IP_HDRINCL, (const char *)&on, sizeof(on)) < 0)
		error_socket("ft_traceroute: error: set IP_HDRINCL option");
	if (setsockopt(g_data.icmp_sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0)
		error_socket("ft_traceroute: error: set timeout option\n");
	timeout.tv_sec = 0;
	timeout.tv_usec = 10;
	if (setsockopt(g_data.icmp_sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0)
	{
		fprintf(stderr, "Setting socket options to timeout failed! %m\n");
		exit(1);
	}
}

void	format_udp_header(int ttl, udp_packet_t *pck)
{
	(void)ttl;
	ft_bzero(pck, sizeof(*pck));
	//printf("seq : %d, ttl : %d\n", g_data.seq, ttl);
	pck->ip_header.ip_hl = sizeof(struct ip) >> 2;  // in words (size is always 20 bytes for IPv4)
	pck->ip_header.ip_v = 4;
	pck->ip_header.ip_tos = 0;
	pck->ip_header.ip_len = sizeof(*pck);
	pck->ip_header.ip_id = g_data.pid + g_data.seq;
	//printf("id : %d\n", pck->ip_header.ip_id);
	pck->ip_header.ip_off = 0;
	pck->ip_header.ip_ttl = ttl;
	pck->ip_header.ip_p = IPPROTO_UDP;
	pck->ip_header.ip_dst = g_data.addr.sin_addr;
	//pck->ip_header.ip_src.s_addr = inet_addr("165.227.229.36");
	pck->ip_header.ip_sum = checksum(&pck, sizeof(pck));

	//printf("ADDR SRC : %s\n", inet_ntoa(pck->ip_header.ip_src));
	//printf("ADDR DEST : %s\n", inet_ntoa(pck->ip_header.ip_dst));

	pck->udp_header.uh_sport = htons(BSWAP16(g_data.pid + g_data.seq));
	pck->udp_header.uh_dport = htons(UDP_PORT + g_data.seq);
	pck->udp_header.uh_ulen = htons(pck->ip_header.ip_len - sizeof(pck->ip_header));
	pck->udp_header.uh_sum = checksum(&pck, sizeof(pck));

	for (unsigned int i = 0; i < sizeof(pck->data); i++)
		pck->data[i] = '@' + i;
}

int		send_packet(udp_packet_t pck)
{
	int				ret;
//	fd_set			write_fds;
//	struct timeval	timeout;

//	FD_SET(g_data.raw_sock, &write_fds);
//	timeout.tv_sec = 1;
//	timeout.tv_usec = 0;

	//if (setsockopt(g_data.raw_sock, IPPROTO_IP, IP_TTL, &g_data.ttl, sizeof(g_data.ttl)) != SUCCESS_CODE)
	//	error_socket("set ttl option failed for value");

	//ret = select(g_data.raw_sock + 1, NULL, &write_fds, NULL, &timeout);
	//if (ret < 0)
	//	return (ERROR_CODE);
	//if (ret == 0)
	//	return (TIMEOUT_CODE);
	ret = sendto(g_data.raw_sock, &pck, sizeof(pck), 0, (struct sockaddr *)&g_data.addr, sizeof(g_data.addr));
	if (ret < 0)
		return (ERROR_CODE);
	return (SUCCESS_CODE);
}

void	format_icmp_header(icmp_packet_t *icmp)
{
	ft_bzero(icmp, sizeof(*icmp));
	icmp->iov.iov_base = icmp->recv_buf;
	icmp->iov.iov_len = sizeof(icmp->recv_buf);
	icmp->mhdr.msg_name = ft_strdup(g_data.addr_ip);
	icmp->mhdr.msg_namelen = sizeof(g_data.addr_ip);
	icmp->mhdr.msg_iov = &icmp->iov;
	icmp->mhdr.msg_iovlen = 1;
	icmp->mhdr.msg_control = &icmp->control;
	icmp->mhdr.msg_controllen = sizeof(&icmp->control);
}

/*
 ** ICMP_TIMXCEED mean the ttl reach to 0, and ICMP_TIMXCEED_INTRANS mean the packet is in transit
*/
int		check_packet(char *buf, struct sockaddr_in *from)
{
	struct ip		*ip;
	struct ip		*ip_icmp;
	struct icmp		*icmp;
	struct udphdr	*udp;

	ip = (struct ip *)buf;
	if (ip->ip_p != IPPROTO_ICMP)
		return (recv_packet());
	icmp = (struct icmp *)(buf + (ip->ip_hl << 2));
	ip_icmp = &icmp->icmp_ip;
	if (ip_icmp->ip_id != g_data.pid + g_data.seq)
		return (recv_packet());
	if (!((icmp->icmp_type == ICMP_TIMXCEED && icmp->icmp_code == ICMP_TIMXCEED_INTRANS) || icmp->icmp_type == ICMP_UNREACH))
		return (ERROR_CODE);
	if (ip_icmp->ip_p != IPPROTO_UDP)
		return (ERROR_CODE);
	if (icmp->icmp_type == ICMP_TIMXCEED)
		return (TIMEOUT_CODE);
	udp = (struct udphdr *)((char *)ip_icmp + (ip_icmp->ip_hl << 2));
	if (udp->uh_dport != htons(UDP_PORT + g_data.seq) || udp->uh_sport != htons(BSWAP16(g_data.pid + g_data.seq)))
		return (ERROR_CODE);
/*	printf("IP : proto :%d, id: %d,  dest :%s, src: %s\n", ip->ip_p, BSWAP16(ip->ip_id), inet_ntoa(ip->ip_dst), inet_ntoa(ip->ip_src));
	printf("ICMP : type: %d, code: %d, seq: %d\n", icmp->icmp_type, icmp->icmp_code, icmp->icmp_seq);
	printf("IP_ICMP : proto :%d, id: %d,  dest :%s, src: %s\n", ip_icmp->ip_p, BSWAP16(ip_icmp->ip_id), inet_ntoa(ip_icmp->ip_dst), inet_ntoa(ip_icmp->ip_src));
	printf("PACKET IP : %d\n", htons(BSWAP16(g_data.pid) + g_data.seq));
	printf("UDP : port dest %d, port src %d, sum %d\n", udp->uh_dport, udp->uh_sport, udp->uh_sum);
	printf("OWN : port dest %d, port src %d\n\n", htons(BSWAP16(UDP_PORT + g_data.seq)),  htons(BSWAP16(g_data.pid + g_data.seq)));
*/
	if (ft_strncmp(inet_ntoa(from->sin_addr), g_data.addr_ip, ft_strlen(g_data.addr_ip)) != 0)
		return (NOT_GOOD_IP);
	return (SUCCESS_CODE);
}

int		recv_packet(struct timeval *time)
{
	struct timeval		end;
	int					ret;
	unsigned int		size;
	char				buf[512];

	ft_bzero(buf, sizeof(buf));
	size = sizeof(struct sockaddr_in);
	ret = recvfrom(g_data.icmp_sock, buf, sizeof(buf), 0, (struct sockaddr *)&g_data.rcv, &size);
	save_time(&end);
	time->tv_sec = end.tv_sec - time->tv_sec;
	time->tv_usec = end.tv_usec - time->tv_usec;
	//printf("Received packet (ret)%d from %s:%d\n", ret, inet_ntoa(rcv.sin_addr), rcv.sin_port);
	if (ret >= 0)
	{
		return (check_packet(buf, &g_data.rcv));
	/*	ip = (struct ip *)buf;
		printf("IP : proto :%d, id: %d,  dest :%s, src: %s\n", ip->ip_p, BSWAP16(ip->ip_id), inet_ntoa(ip->ip_dst), inet_ntoa(ip->ip_src));
		if (ip->ip_p != IPPROTO_ICMP)
			return (1);
		ret_icmp = (struct icmp *)(buf + (ip->ip_hl << 2));
		printf("ICMP : type: %d, code: %d, seq: %d\n", ret_icmp->icmp_type, ret_icmp->icmp_code, ret_icmp->icmp_seq);
		struct ip *ip_icmp = &ret_icmp->icmp_ip;
		printf("IP_ICMP : proto :%d, id: %d,  dest :%s, src: %s\n", ip_icmp->ip_p, BSWAP16(ip_icmp->ip_id), inet_ntoa(ip_icmp->ip_dst), inet_ntoa(ip_icmp->ip_src));
		struct udphdr *udp = (struct udphdr *)((unsigned char *)ip_icmp + (ip_icmp->ip_hl << 2));
		printf("UDP : port dest %d, port src %d, sum %d\n", udp->uh_dport, udp->uh_sport, udp->uh_sum);
		printf("OWN : port dest %d, port src %d\n", htons(BSWAP16(UDP_PORT + g_data.seq)),  htons(BSWAP16(g_data.pid + g_data.seq)));
	*/}
	else
	{
		//if (errno == EAGAIN /*&& g_data.flags & FLAG_V*/)
			//printf("Request " Blue "timeout" White " for icmp_seq %d\n", g_data.seq);
		//g_data.lose_msg++;
	}
	return (ERROR_CODE);
}

void	save_time(struct timeval *time)
{
	if (gettimeofday(time, NULL))
	{
		free_traceroute();
		exit(1);
	}
}

void	print_packet(int round, int ttl, struct timeval time, int code)
{
	double	time_value;
	char	*new_addr;
	static int	error = 0;

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
			printf("%s (%s)  %.3lf ms", new_addr, new_addr, time_value);
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
}

void	loop_traceroute()
{
	int				ret;
	bool			end;
	udp_packet_t	udp_pck;
	struct timeval	time;

	g_data.ttl = 1;
	end = false;
	while (g_data.ttl <= MAX_HOP && !end)
	{
		for (int round = 0; round < MAX_ROUND; round++)
		{
			format_udp_header(g_data.ttl, &udp_pck);
			save_time(&time);
			ret = send_packet(udp_pck);
			if (ret == ERROR_CODE)
				printf("Send packet seq %d failed\n", g_data.seq);
			else
			{
				//format_icmp_header(&icmp_pck);
				if ((ret = recv_packet(&time)) == SUCCESS_CODE)
				{
					print_packet(round, g_data.ttl, time, ret);
					//printf("%d.%d %s %.3lfms\n", g_data.ttl, round, g_data.last_ip, (double)(((double)time.tv_sec * 1000) + ((double)time.tv_usec / 1000)));
					end = true;
				}
				else if (ret == TIMEOUT_CODE)
					print_packet(round, g_data.ttl, time, ret);
					//printf("%d.%d %s %.3lfms\n", g_data.ttl, round, g_data.last_ip, (double)(((double)time.tv_sec * 1000) + ((double)time.tv_usec / 1000)));
				else
					print_packet(round, g_data.ttl, time, ret);
					//printf("%d.%d *\n", g_data.ttl, round);
				//if (ret != ERROR_CODE)
				//	g_data.last_ip = inet_ntoa(g_data.rcv.sin_addr);
			}
			g_data.seq++;
		}
		g_data.ttl++;
	}
	printf("\nEND\n");
}
void	init()
{
	g_data.pid = getpid();
	g_data.seq = 1;
	g_data.ttl = 1;
	g_data.last_ip = NULL;
}

int		main(int ac, char **av)
{
	if (ac <= 1)
	{
		print_usage();
		exit(1);
	}
	dns_lookup(av[ac - 1]);
	init();
	create_socket();
	loop_traceroute();
	free_traceroute();
}
