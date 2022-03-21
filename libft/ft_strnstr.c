/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strnstr.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: lmoulin <marvin@42.fr>                     +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/10/07 15:17:23 by lmoulin           #+#    #+#             */
/*   Updated: 2019/10/17 14:28:44 by lmoulin          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <stdlib.h>

char	*ft_strnstr(const char *haystack, const char *needle, size_t len)
{
	size_t	i;
	size_t	k;

	i = 0;
	if (!*needle)
		return ((char*)haystack);
	while (haystack[i] != '\0' && i < len)
	{
		k = 0;
		if (haystack[i] == needle[k])
		{
			while (needle[k] && haystack[i + k] == needle[k] && i + k < len)
				k++;
			if (needle[k] == '\0')
				return ((char*)&haystack[i]);
		}
		i++;
	}
	return (0);
}
