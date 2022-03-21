#include "../inc/ft_traceroute.h"

void	print_usage()
{
	printf("Usage: ft_traceroute: destination\n");
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
	freeaddrinfo(res);
}

void	free_traceroute()
{
	if (g_data.addr_ip)
		free(g_data.addr_ip);
}

int		main(int ac, char **av)
{
	if (ac <= 1)
	{
		print_usage();
		exit(1);
	}

	dns_lookup(av[ac - 1]);
	free_traceroute();
}
