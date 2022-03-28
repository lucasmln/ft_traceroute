#include "../inc/ft_traceroute.h"

void	print_usage()
{
	printf("Usage: ft_traceroute: destination\n");
}

void	free_traceroute()
{
	if (g_data.addr_ip)
		free(g_data.addr_ip);
	close(g_data.icmp_sock);
	close(g_data.raw_sock);
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
	char	*reverse_addr;
	static int	error = 0;

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

char	*reverse_dns_lookup(struct sockaddr_in add)
{
	char	buf[65];

	if (getnameinfo((struct sockaddr *)&add, sizeof(struct sockaddr_in),
		buf, sizeof(buf), NULL, 0, NI_NAMEREQD) == 0)
		return (ft_strdup(buf));
	return (NULL);
}

struct timeval	timeval_sub(struct timeval *a, struct timeval *b)
{
	struct timeval	res;

	res.tv_sec = a->tv_sec - b->tv_sec;
	res.tv_usec = a->tv_usec - b->tv_usec;
	return (res);
}
