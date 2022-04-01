#include "../inc/ft_traceroute.h"

void			save_time(struct timeval *time)
{
	if (gettimeofday(time, NULL))
	{
		free_traceroute();
		exit(1);
	}
}

struct timeval	timeval_sub(struct timeval *a, struct timeval *b)
{
	struct timeval	res;

	res.tv_sec = a->tv_sec - b->tv_sec;
	res.tv_usec = a->tv_usec - b->tv_usec;
	return (res);
}

void			wait_time(double time_sec)
{
	struct timeval		init;
	struct timeval		goal;
	int					sec = (int)time_sec;

	save_time(&init);
	goal = init;
	goal.tv_sec += sec;
	goal.tv_usec += (time_sec - sec) * USEC;
	if (goal.tv_usec >= USEC)
	{
		goal.tv_sec += 1;
		goal.tv_usec -= USEC;
	}
	while (1)
	{
		save_time(&init);
		if (goal.tv_sec - init.tv_sec <= 0)
		{
			if (goal.tv_sec - init.tv_sec < 0)
				break;
			else if (goal.tv_usec - init.tv_usec <= 0)
				break;
		}
	}
}
