/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strchr.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: lmoulin <marvin@42.fr>                     +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/10/07 14:34:03 by lmoulin           #+#    #+#             */
/*   Updated: 2019/10/21 15:57:06 by lmoulin          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char	*ft_strchr(const char *s, int c)
{
	char	*pos;

	if (!s)
		return (NULL);
	pos = (char *)s;
	while (*pos != c)
	{
		if (!*pos)
			return (0);
		pos++;
	}
	return (pos);
}
