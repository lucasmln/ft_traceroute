#ifndef FT_TRACEROUTE_H
# define FT_TRACEROUTE_H

# include <stdio.h>
# include <stdlib.h>
# include <sys/socket.h>
# include <sys/types.h>
# include <netdb.h>
# include <arpa/inet.h>
# include "../libft/libft.h"


typedef struct		ft_traceroute_s
{
	int					sock;
	struct sockaddr_in	addr;
	char				*addr_ip;

}					ft_traceroute_t;

ft_traceroute_t		g_data;

#endif
