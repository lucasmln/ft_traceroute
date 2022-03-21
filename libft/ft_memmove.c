/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_memmove.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: lmoulin <marvin@42.fr>                     +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/10/08 12:24:28 by lmoulin           #+#    #+#             */
/*   Updated: 2019/10/15 14:32:24 by lmoulin          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <string.h>
#include "libft.h"

void	*ft_memmove(void *dst, const void *src, size_t len)
{
	const char	*s;
	char		*d;

	if ((!dst && !src) || !len)
		return (dst);
	s = src;
	d = dst;
	if (dst <= src)
		return (ft_memcpy(dst, src, len));
	while (len-- > 0)
		d[len] = s[len];
	return (d);
}
