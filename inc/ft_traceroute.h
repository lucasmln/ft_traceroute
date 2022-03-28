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
# define INVALID_PACKET 4

# define BSWAP16(x)			((__uint16_t) ((((x) >> 8) & 0xff) | (((x) & 0xff) << 8)))

# define FLAGS_I 0b00000001 // Send ICMP packets
# define FLAGS_W 0b00000010 // Set wait time for response
# define FLAGS_Z 0b00000100 // Set interval time between probes

# define Green "\033[0;32m"
# define Red "\033[0;31m"
# define White "\033[0;37m"
# define Blue "\033[0;34m"
# define Yellow "\033[0;33m"

typedef struct		udp_packet_s
{
	struct ip		ip_header;
	struct udphdr	udp_header;
	char			data[60 - sizeof(struct udphdr) - sizeof(struct ip)];
}					udp_packet_t;

typedef struct		icmp_packet_s
{
	//struct ip		ip_header;
	struct icmp		icmp_header;
	char			data[60 - sizeof(struct icmp) - sizeof(struct ip)];
}					icmp_packet_t;


typedef struct		ft_traceroute_s
{
	int					raw_sock;
	int					icmp_sock;
	int					pid;
	struct sockaddr_in	addr;
	struct sockaddr_in	rcv;
	void				*pck;
	char				*last_ip;
	char				*addr_ip;
	int					ttl;
	int					seq;
	int					flags;
	double				wait_recv;
	double				wait_probes;
}					ft_traceroute_t;

ft_traceroute_t		g_data;


void	save_time(struct timeval *time);

/*
 ** socket.c
*/
void	create_socket();
void	error_socket(const char *error);
void	dns_lookup(const char *dest);

/*
 ** packet.c
*/
void	format_udp_header(int ttl, udp_packet_t *pck);
int		send_packet(void *pck);
int		rcv_packet(struct timeval *time);
int		check_packet(char *buf, struct sockaddr_in *from, struct timeval *time);
unsigned short	checksum(void *address, int len);


/*
 ** parse.c
*/
void	parse(int ac, char **av);
void	check_option(int ac, char **av, int i);

/*
 ** utils.c
*/
void	free_traceroute();
void	save_time(struct timeval *time);
void	print_packet(int round, int ttl, struct timeval time, int code);
char	*reverse_dns_lookup(struct sockaddr_in add);
void	print_usage();
struct timeval	timeval_sub(struct timeval *a, struct timeval *b);

#endif
