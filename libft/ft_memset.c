/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_memset.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: lmoulin <marvin@42.fr>                     +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/10/07 16:22:05 by lmoulin           #+#    #+#             */
/*   Updated: 2019/10/09 11:09:40 by lmoulin          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <stdio.h>

void	*ft_memset(void *b, int c, size_t len)
{
	unsigned int	i;
	char			*tab;

	i = 0;
	tab = (char*)b;
	while (i < len)
	{
		*tab = c;
		tab++;
		i++;
	}
	return (b);
}
