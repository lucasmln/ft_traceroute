#include "../inc/ft_traceroute.h"

void	format_udp_header(int ttl, udp_packet_t *pck)
{
	int				data_len;
	int				len;
	unsigned int	i;

	data_len = g_data.packet_len - sizeof(struct ip) - sizeof(struct udphdr);
	data_len = data_len < 0 ? 0 : data_len;
	len = data_len + sizeof(struct ip) + sizeof(struct udphdr);
	ft_bzero(pck, sizeof(*pck));
	pck->ip_header.ip_hl = sizeof(struct ip) >> 2;  // in words (size is always 20 bytes for IPv4)
	pck->ip_header.ip_v = 4;
	pck->ip_header.ip_tos = 0;
	pck->ip_header.ip_len = len;
	pck->ip_header.ip_id = g_data.pid + g_data.seq - 1;
	pck->ip_header.ip_off = 0;
	pck->ip_header.ip_ttl = ttl;
	pck->ip_header.ip_p = IPPROTO_UDP;
	pck->ip_header.ip_dst = g_data.addr.sin_addr;
	pck->ip_header.ip_sum = checksum(&pck, sizeof(pck));
	pck->udp_header.uh_sport = htons(UDP_PORT + g_data.pid + g_data.seq);
	pck->udp_header.uh_dport = htons(g_data.default_port + g_data.seq);
	pck->udp_header.uh_ulen = htons(len - sizeof(pck->ip_header));
	pck->udp_header.uh_sum = 0;
	for (i = 0; i < sizeof(pck->data); i++)
		pck->data[i] = '@' + (i % (127 - '@'));
	pck->data[i] = '\0';
}

void	format_icmp_header(int ttl, icmp_packet_t *icmp)
{
	int		data_len;
	int		i;

	data_len = g_data.packet_len - sizeof(struct icmp);
	data_len = data_len < 0 ? 0 : data_len;
	ft_bzero(icmp, sizeof(*icmp));
	icmp->icmp_header.type = ICMP_ECHO;
	icmp->icmp_header.code = 0;
	icmp->icmp_header.un.echo.id = BSWAP16(g_data.pid);
	icmp->icmp_header.un.echo.sequence = BSWAP16(g_data.seq);
	if (setsockopt(g_data.icmp_sock, SOL_IP, IP_TTL, &ttl, sizeof(ttl)) != 0)
		error_socket("Set TTL failed\n");
	i = 0;
	for (i = 0; i < data_len; i++)
		icmp->data[i] = '@' + (i % (127 - '@'));
	icmp->data[0] = '\0';
	icmp->icmp_header.checksum = checksum(icmp, sizeof(struct icmphdr) + data_len);
}

int		send_packet(void *pck)
{
	int				ret;
	int				data_len;
	int				len;

	if (g_data.flags & FLAGS_I)
	{
		data_len = g_data.packet_len - sizeof(struct icmp);
		data_len = data_len < 0 ? 0 : data_len;
		len = data_len + sizeof(struct icmphdr);
		ret = sendto(g_data.icmp_sock, (icmp_packet_t *)pck, len, 0, (struct sockaddr *)&g_data.addr, sizeof(g_data.addr));
	}
	else
	{
		data_len = g_data.packet_len - sizeof(struct ip) - sizeof(struct udphdr);
		data_len = data_len < 0 ? 0 : data_len;
		len = data_len + sizeof(struct ip) + sizeof(struct udphdr);
		ret = sendto(g_data.raw_sock, (udp_packet_t *)pck, len, 0, (struct sockaddr *)&g_data.addr, sizeof(g_data.addr));
	}
	if (ret < 0)
		return (ERROR_CODE);
	return (SUCCESS_CODE);
}


int		rcv_packet(struct timeval *time)
{
	unsigned int		size;
	char				buf[512];
	fd_set				fds;
	struct timeval		timeout;
	int					ret;

	FD_ZERO(&fds);
	FD_SET(g_data.icmp_sock, &fds);
	ft_bzero(buf, sizeof(buf));
	size = sizeof(struct sockaddr_in);
	ft_bzero(&g_data.rcv, size);
	timeout.tv_sec = (int)g_data.wait_recv;
	timeout.tv_usec = ((double)(g_data.wait_recv - (int)g_data.wait_recv)) * USEC;
	if ((ret = select(g_data.icmp_sock + 1, &fds, NULL, NULL, &timeout)) > 0)
	{
		if (recvfrom(g_data.icmp_sock, buf, sizeof(buf), 0, (struct sockaddr *)&g_data.rcv, &size) < 0)
			return (ERROR_CODE);
		return (check_packet(buf, &g_data.rcv, time));
	}
	return (ERROR_CODE);
}

int		check_icmp_packet(char *buf, struct sockaddr_in *from, struct ip *ip, struct timeval *time)
{
	struct icmp		*icmp;
	struct icmp		*tmp;

	icmp = (struct icmp *)(buf + (ip->ip_hl << 2));
	if (!((icmp->icmp_type == ICMP_TIMXCEED && icmp->icmp_code == ICMP_TIMXCEED_INTRANS) ||
		icmp->icmp_type == ICMP_UNREACH || (g_data.flags & FLAGS_I && icmp->icmp_code == ICMP_ECHOREPLY)))
		return (rcv_packet(time));
	if (icmp->icmp_type == ICMP_TIMXCEED)
	{
		tmp = (struct icmp *)(icmp + 1);
		if (BSWAP16(tmp->icmp_id) != g_data.pid || BSWAP16(tmp->icmp_seq) != g_data.seq)
			return (rcv_packet(time));
		return (ICMP_TIMXCEED);
	}
	if (BSWAP16(g_data.pid) != icmp->icmp_id && BSWAP16(g_data.seq) != icmp->icmp_seq)
		return (rcv_packet(time));
	if (ft_strncmp(inet_ntoa(from->sin_addr), g_data.addr_ip, ft_strlen(g_data.addr_ip)) != 0)
		return (ERROR_CODE);
	return (SUCCESS_CODE);
}

int		check_udp_packet(char *buf, struct sockaddr_in *from, struct ip *ip, struct timeval *time)
{
	struct udphdr	*udp;
	struct icmp		*icmp;
	struct ip		*ip_icmp;

	icmp = (struct icmp *)(buf + (ip->ip_hl << 2));
	ip_icmp = &icmp->icmp_ip;
	if (ip_icmp->ip_id != g_data.pid + g_data.seq - 1)
		return (rcv_packet(time));
	if (!((icmp->icmp_type == ICMP_TIMXCEED && icmp->icmp_code == ICMP_TIMXCEED_INTRANS) ||
		icmp->icmp_type == ICMP_UNREACH))
		return (rcv_packet(time));
	if (icmp->icmp_type == ICMP_UNREACH && icmp->icmp_code != ICMP_PORT_UNREACH)
	{
		g_data.unreach_error = icmp->icmp_code;
		return (UNREACH_CODE);
	}
	if (ip_icmp->ip_p != IPPROTO_UDP)
		return (ERROR_CODE);
	udp = (struct udphdr *)((char *)ip_icmp + (ip_icmp->ip_hl << 2));
	if (icmp->icmp_type == ICMP_TIMXCEED)
	{
		if (udp->uh_dport != htons(g_data.default_port + g_data.seq) || udp->uh_sport != htons(UDP_PORT + g_data.pid + g_data.seq))
			return (rcv_packet(time));
		return (ICMP_TIMXCEED);
	}
	if (ft_strncmp(inet_ntoa(from->sin_addr), g_data.addr_ip, ft_strlen(g_data.addr_ip)) != 0)
		return (rcv_packet(time));
	return (SUCCESS_CODE);
}

/*
 ** ICMP_TIMXCEED mean the ttl reach to 0, and ICMP_TIMXCEED_INTRANS mean the packet is in transit
*/
int		check_packet(char *buf, struct sockaddr_in *from, struct timeval *time)
{
	struct ip		*ip;

	ip = (struct ip *)buf;
	if (ip->ip_p == IPPROTO_ICMP && g_data.flags & FLAGS_I)
		return (check_icmp_packet(buf, from, ip, time));
	else if (ip->ip_p == IPPROTO_ICMP && !(g_data.flags & FLAGS_I))
		return (check_udp_packet(buf, from, ip, time));
	return (rcv_packet(time));
}
