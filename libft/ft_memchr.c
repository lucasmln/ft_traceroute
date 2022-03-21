/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_memchr.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: lmoulin <marvin@42.fr>                     +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/10/08 14:03:26 by lmoulin           #+#    #+#             */
/*   Updated: 2019/10/11 15:23:45 by lmoulin          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <stdlib.h>

void	*ft_memchr(const void *s, int c, size_t n)
{
	char	*str;
	int		i;

	str = (char*)s;
	i = 0;
	while (n-- > 0)
	{
		if (str[i] == c)
			return (str + i);
		i++;
	}
	return (NULL);
}
