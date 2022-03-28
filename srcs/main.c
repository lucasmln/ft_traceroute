#include "../inc/ft_traceroute.h"

void	format_icmp_header(int ttl, icmp_packet_t *icmp)
{
	ft_bzero(icmp, sizeof(*icmp));
	icmp->icmp_header.icmp_type = ICMP_ECHO;
	icmp->icmp_header.icmp_code = 0;
	icmp->icmp_header.icmp_id = BSWAP16(g_data.pid);
	icmp->icmp_header.icmp_seq = BSWAP16(g_data.seq);
	icmp->icmp_header.icmp_cksum = checksum(icmp, sizeof(*icmp));
	if (setsockopt(g_data.icmp_sock, SOL_IP, IP_TTL, &ttl, sizeof(ttl)) != 0)
		error_socket("Set TTL failed\n");
}

void	loop_traceroute()
{
	int				ret;
	bool			end;
	udp_packet_t	udp_pck;
	icmp_packet_t	icmp_pck;
	struct timeval	send_time;
	struct timeval	recv_time;

	g_data.ttl = 1;
	end = false;
	while (g_data.ttl <= MAX_HOP && end == false)
	{
		for (int round = 0; round < MAX_ROUND; round++)
		{
			if (g_data.flags & FLAGS_I)
			{
				format_icmp_header(g_data.ttl, &icmp_pck);
				g_data.pck = (void *)&icmp_pck;
			}
			else
			{
				format_udp_header(g_data.ttl, &udp_pck);
				g_data.pck = (void *)&udp_pck;
			}
			save_time(&send_time);
			ret = send_packet(g_data.pck);
			if (ret == ERROR_CODE)
				printf("Send packet seq %d failed\n", g_data.seq);
			else
			{
				ret = rcv_packet(&recv_time);
				save_time(&recv_time);
				if (ret == SUCCESS_CODE)
				{
					print_packet(round, g_data.ttl, timeval_sub(&recv_time, &send_time), ret);
					end = true;
				}
				else if (ret == ICMP_TIMXCEED)
					print_packet(round, g_data.ttl, timeval_sub(&recv_time, &send_time), ret);
				if (ret == ERROR_CODE)
					print_packet(round, g_data.ttl, timeval_sub(&recv_time, &send_time), ret);
			}
			g_data.seq++;
		}
		g_data.ttl++;
	}
}
void	init()
{
	g_data.pid = getpid();
	g_data.seq = 1;
	g_data.ttl = 1;
	g_data.flags = 0;
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
	parse(ac, av);
	create_socket();
	loop_traceroute();
	free_traceroute();
}
