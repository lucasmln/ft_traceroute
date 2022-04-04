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
# define USEC 1000000
# define PACKET_LEN_MAX 70000
# define MTU 1500

# define SUCCESS_CODE 0
# define ERROR_CODE 1
# define UNREACH_CODE 2

# define BSWAP16(x)			((__uint16_t) ((((x) >> 8) & 0xff) | (((x) & 0xff) << 8)))

# define FLAGS_I 0b00000001 // Send ICMP packets
# define FLAGS_W 0b00000010 // Set wait time for response
# define FLAGS_Z 0b00000100 // Set interval time between probes
# define FLAGS_F 0b00001000 // Set the value of the first ttl
# define FLAGS_M 0b00010000 // Set the max ttl value
# define FLAGS_N 0b00100000 // Do not map ip addresses with host names
# define FLAGS_P 0b01000000 // For UDP set the destination port. It will be incremented. For ICMP set the sequence value
# define FLAGS_Q 0b10000000 // Set the number of probe packet per hop. The default is 3


typedef struct		udp_packet_s
{
	struct ip		ip_header;
	struct udphdr	udp_header;
	uint8_t			data[PACKET_LEN_MAX + 1];//char			data[60 - sizeof(struct udphdr) - sizeof(struct ip)];
}					udp_packet_t;

typedef struct		icmp_packet_s
{
	struct icmphdr	icmp_header;
	uint8_t			data[PACKET_LEN_MAX + 1];
}					icmp_packet_t;


typedef struct		ft_traceroute_s
{
	int					raw_sock;
	int					icmp_sock;
	struct sockaddr_in	addr;
	struct sockaddr_in	rcv;
	void				*pck;
	char				*last_ip;
	char				*addr_ip;
	int					pid;
	int					ttl;
	int					seq;
	int					nb_probes;
	int					ttl_max;
	int					packet_len;
	int					flags;
	unsigned int		default_port;
	int					unreach_error;
	double				wait_recv;
	double				wait_probes;
}					ft_traceroute_t;

ft_traceroute_t		g_data;


/*
 ** main.c
*/
void			free_traceroute();
void			loop_traceroute();
void			init();

/*
 ** socket.c
*/
void			create_socket();
void			error_socket(const char *error);
void			dns_lookup(const char *dest);
char			*reverse_dns_lookup(struct sockaddr_in add);

/*
 ** packet.c
*/
void			format_udp_header(int ttl, udp_packet_t *pck);
int				send_packet(void *pck);
int				rcv_packet(struct timeval *time);
int				check_packet(char *buf, struct sockaddr_in *from, struct timeval *time);
void			format_icmp_header(int ttl, icmp_packet_t *icmp);


/*
 ** parse.c
*/
void			parse(int ac, char **av, int *addr_pos);
void			get_options(int ac, char **av, int *i);
void			check_flags();
int				get_packet_len(char **av, int ac, int *i);
char			get_flag(char *flag);
void			set_flag_dvalue(double *dst, int pos, char **av, int ac);
void			set_flag_ivalue(int *dst, int pos, char **av, int ac);

/*
 ** utils.c
*/
void			print_traceroute_hdr(char *dst, char *dns_dst, int hops, long unsigned int pck_size);
void			print_packet(int round, int ttl, struct timeval time, int code);
void			print_usage();
unsigned short	checksum(void *address, int len);

/*
 ** time.c
*/
void			wait_time(double time_sec);
void			save_time(struct timeval *time);
struct timeval	timeval_sub(struct timeval *a, struct timeval *b);

#endif
