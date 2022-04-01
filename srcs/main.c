#include "../inc/ft_traceroute.h"

void	loop_traceroute()
{
	int				ret;
	bool			end;
	udp_packet_t	udp_pck;
	icmp_packet_t	icmp_pck;
	struct timeval	send_time;
	struct timeval	recv_time;

	end = false;
	while (g_data.ttl <= g_data.ttl_max && end == false)
	{
		for (int round = 0; round < g_data.nb_probes; round++)
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
			//fflush(stdout);
			g_data.seq++;
			if (g_data.flags & FLAGS_Z && g_data.wait_probes > 0)
				wait_time(g_data.wait_probes);
		}
		g_data.ttl++;
	}
}

void	free_traceroute()
{
	if (g_data.addr_ip)
		free(g_data.addr_ip);
	if (g_data.last_ip)
		free(g_data.last_ip);
	close(g_data.icmp_sock);
	close(g_data.raw_sock);
}

void	init()
{
	g_data.pid = getpid();
	g_data.seq = 1;
	g_data.ttl = 1;
	g_data.flags = 0;
	g_data.wait_probes = 0;
	g_data.wait_recv = 5;
	g_data.ttl_max = MAX_HOP;
	g_data.nb_probes = MAX_ROUND;
	g_data.default_port = UDP_PORT;
	g_data.last_ip = NULL;
}

int		main(int ac, char **av)
{
	int		addr_pos;

	addr_pos = 0;
	if (ac <= 1)
	{
		print_usage();
		exit(1);
	}
	init();
	parse(ac, av, &addr_pos);
	if (addr_pos == 0)
	{
		printf("Specify %chost%c missing argument.\n", '"', '"');
		exit(2);
	}
	dns_lookup(av[addr_pos]);
	create_socket();
	print_traceroute_hdr(av[addr_pos], g_data.addr_ip, g_data.ttl_max, g_data.packet_len);
	loop_traceroute();
	free_traceroute();
}
