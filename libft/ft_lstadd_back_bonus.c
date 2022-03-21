/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_lstadd_back_bonus.c                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: lmoulin <marvin@42.fr>                     +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/10/15 18:08:00 by lmoulin           #+#    #+#             */
/*   Updated: 2019/10/15 18:20:31 by lmoulin          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

void	ft_lstadd_back(t_list **alst, t_list *now)
{
	t_list		*temp;

	if (!now || !alst)
		return ;
	temp = *alst;
	if (*alst == NULL)
		*alst = now;
	else
	{
		while (temp->next)
			temp = temp->next;
		temp->next = now;
	}
}
