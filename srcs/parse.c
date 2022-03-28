#include "../inc/ft_traceroute.h"

void	parse(int ac, char **av)
{
	for (int i = 0; i < ac; i++)
	{
		if (av[i][0] == '-')
			check_option(ac, av, i);
	}
}

void	check_option(int ac, char **av, int i)
{
	(void)ac;
	if (ft_strncmp(av[i], "-I", ft_strlen(av[i])) == 0)
	{
		g_data.flags = g_data.flags | FLAGS_I;
	}
	if (ft_strncmp(av[i], "-w", ft_strlen(av[i])) == 0)
	{
		g_data.flags = g_data.flags | FLAGS_W;
		if (i + 1 >= ac)
			g_data.wait_recv = -1;
		else
			g_data.wait_recv = atof(av[i + 1]);
	}
	if (ft_strncmp(av[i], "-z", ft_strlen(av[i])) == 0)
	{
		g_data.flags = g_data.flags | FLAGS_Z;
		if (i + 1 >= ac)
			g_data.wait_probes = -1;
		else
			g_data.wait_probes = atof(av[i + 1]);
	}


}
