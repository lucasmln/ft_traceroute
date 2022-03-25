#ifndef FT_TRACEROUTE_H
# define FT_TRACEROUTE_H

# include <stdio.h>
# include <stdlib.h>
# include <sys/socket.h>
# include <sys/types.h>
# include <netdb.h>
# include <arpa/inet.h>
# include <netinet/ip_icmp.h>
# include <netinet/udp.h>
# include <sys/time.h>
# include <stdbool.h>
# include <errno.h>
# include <string.h>
# include "../libft/libft.h"

# define UDP_PORT 33434
# define MAX_ROUND 3
# define MAX_HOP 30

# define SUCCESS_CODE 0
# define ERROR_CODE 1
# define TIMEOUT_CODE 2
# define NOT_GOOD_IP 3

# define BSWAP16(x)			((__uint16_t) ((((x) >> 8) & 0xff) | (((x) & 0xff) << 8)))

# define Green "\033[0;32m"
# define Red "\033[0;31m"
# define White "\033[0;37m"
# define Blue "\033[0;34m"
# define Yellow "\033[0;33m"

typedef struct		icmp_packet_s
{
	int				ret;
	struct msghdr	mhdr;
	struct iovec	iov;
	char			control[CMSG_SPACE(sizeof(int))];
	char			recv_buf[84];

}					icmp_packet_t;

typedef struct		udp_packet_s
{
	struct ip		ip_header;
	struct udphdr	udp_header;
	char			data[60 - sizeof(struct udphdr) - sizeof(struct ip)];
}					udp_packet_t;

typedef struct		ft_traceroute_s
{
	int					raw_sock;
	int					icmp_sock;
	int					pid;
	struct sockaddr_in	addr;
	struct sockaddr_in	rcv;
	char				*last_ip;
	char				*addr_ip;
	int					ttl;
	int					seq;
}					ft_traceroute_t;

ft_traceroute_t		g_data;


int		recv_packet();
void	save_time(struct timeval *time);

#endif
