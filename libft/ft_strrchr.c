/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strrchr.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: lmoulin <marvin@42.fr>                     +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/10/07 14:48:40 by lmoulin           #+#    #+#             */
/*   Updated: 2019/10/17 14:45:45 by lmoulin          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <stdlib.h>

char	*ft_strrchr(const char *s, int c)
{
	char	*pos;

	pos = 0;
	while (*s)
	{
		if (*s == c)
			pos = (char*)s;
		s++;
	}
	if (pos)
		return (pos);
	if (c == '\0')
		return ((char*)s);
	return (0);
}
