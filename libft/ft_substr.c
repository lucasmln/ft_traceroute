/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_substr.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: lmoulin <marvin@42.fr>                     +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/10/08 16:02:31 by lmoulin           #+#    #+#             */
/*   Updated: 2019/10/21 15:38:22 by lmoulin          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char	*ft_substr(char const *s, unsigned int start, size_t len)
{
	char	*new;
	size_t	k;
	size_t	i;

	i = 0;
	if (!s)
		return (NULL);
	len = (start > ft_strlen(s)) ? 0 : len;
	while (i < len && s[start + i])
		i++;
	if (!(new = malloc((i + 1) * sizeof(char))))
		return (NULL);
	k = 0;
	while (i > k)
	{
		new[k] = s[start + k];
		k++;
	}
	new[k] = '\0';
	return (new);
}
