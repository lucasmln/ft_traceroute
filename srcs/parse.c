#include "../inc/ft_traceroute.h"

void	parse(int ac, char **av, int *addr_pos)
{
	int		pos;

	pos = 0;
	for (int i = 1; i < ac; i++)
	{
		if (av[i][0] == '-')
			get_options(ac, av, &i);
		else if (*addr_pos == 0)
		{
			*addr_pos = i;
			g_data.packet_len = get_packet_len(av, ac, &i);
		}
		else
		{
			printf("Extra arg `%s` (position %d, argc %d)\n", av[i], pos, i);
			exit(2);
		}
		pos++;
	}
	check_flags();
}

void	get_options(int ac, char **av, int *i)
{
	switch (get_flag(av[*i]))
	{
		case 'h':
			print_usage();
			exit(0);
			break;
		case 'f':
			g_data.flags = g_data.flags | FLAGS_F;
			set_flag_ivalue(&g_data.ttl, *i + 1, av, ac);
			(*i)++;
			break;
		case 'I':
			g_data.flags = g_data.flags | FLAGS_I;
			break;
		case 'm':
			g_data.flags = g_data.flags | FLAGS_M;
			set_flag_ivalue(&g_data.ttl_max, *i + 1, av, ac);
			(*i)++;
			break;
		case 'n':
			g_data.flags = g_data.flags | FLAGS_N;
			break;
		case 'p':
			g_data.flags = g_data.flags | FLAGS_P;
			set_flag_ivalue((int *)&g_data.default_port, *i + 1, av, ac);
			(*i)++;
			break;
		case 'q':
			g_data.flags = g_data.flags | FLAGS_Q;
			set_flag_ivalue(&g_data.nb_probes, *i + 1, av, ac);
			(*i)++;
			break;
		case 'w':
			g_data.flags = g_data.flags | FLAGS_W;
			set_flag_dvalue(&g_data.wait_recv, *i + 1, av, ac);
			(*i)++;
			break;
		case 'z':
			g_data.flags = g_data.flags | FLAGS_Z;
			set_flag_dvalue(&g_data.wait_probes, *i + 1, av, ac);
			(*i)++;
			break;
		default:
			printf("Bad option `%s` (argc %d)\n", av[*i], *i);
			exit(2);
			break;
	}
}

int		get_packet_len(char **av, int ac, int *i)
{
	if (*i + 1 >= ac)
		return (60);
	(*i)++;
	return (ft_atoi(av[*i]));
}

void	check_flags()
{
	int		error;

	error = 0;
	if (g_data.flags & FLAGS_W && g_data.wait_recv < 0 && ++error)
		printf("bad wait specifications `%.2lf` used\n", g_data.wait_recv);
	else if (g_data.flags & FLAGS_Z && g_data.wait_probes < 0 && ++error)
		printf("bad sendtime `%.2lf' specified\n", g_data.wait_probes);
	else if (g_data.flags & FLAGS_Q && (g_data.nb_probes > 10 || g_data.nb_probes < 0) && ++error)
		printf("no more than 10 probes per hop\n");
	else if (g_data.flags & FLAGS_M && (g_data.ttl_max > 255 || g_data.ttl_max < 0) && ++error)
		printf("max hops cannot be more than 255\n");
	else if (g_data.flags & FLAGS_F && (g_data.ttl > g_data.ttl_max || g_data.ttl < 0) && ++error)
		printf("first hop out of range\n");
	else if (g_data.packet_len > MTU && ++error)
		printf("too big packet_len %d specified. MTU is %d\n", g_data.packet_len, MTU);

	if (error)
	{
		free_traceroute();
		exit(1);
	}
	g_data.wait_probes = g_data.wait_probes >= 10 ? g_data.wait_probes / 1000 : g_data.wait_probes;
	if (g_data.flags & FLAGS_I && g_data.flags & FLAGS_P)
		g_data.seq = g_data.seq;
}

char	get_flag(char *flag)
{
	if (ft_strlen(flag) <= 1)
		return (0);
	if (flag[1] == '-')
	{
		if (!ft_strncmp(flag, "--icmp", ft_strlen("--icmp")) && ft_strlen("--icmp") == ft_strlen(flag))
			return ('I');
		else if (!ft_strncmp(flag, "--help", ft_strlen("--help")) && ft_strlen("--help") == ft_strlen(flag))
			return ('h');
	}
	return (flag[1]);
}

void	set_flag_dvalue(double *dst, int pos, char **av, int ac)
{
	if (pos >= ac || !ft_isdigit(av[pos][0]))
		*dst = -1;
	else
		*dst = atof(av[pos]);
}

void	set_flag_ivalue(int *dst, int pos, char **av, int ac)
{
	if (pos >= ac)
		*dst = -1;
	else
		*dst = ft_atoi(av[pos]);
}


