# **************************************************************************** #
#                                                                              #
#                                                         :::      ::::::::    #
#    Makefile                                           :+:      :+:    :+:    #
#                                                     +:+ +:+         +:+      #
#    By: lmoulin <marvin@42.fr>                     +#+  +:+       +#+         #
#                                                 +#+#+#+#+#+   +#+            #
#    Created: 2022/02/28 19:46:42 by lmoulin           #+#    #+#              #
#    Updated: 2022/02/28 19:51:18 by lmoulin          ###   ########.fr        #
#                                                                              #
# **************************************************************************** #

NAME = ft_traceroute

SRC = main.c

DIR_SRC = ./srcs/

SRCS = $(addprefix $(DIR_SRC), $(SRC))

CFLAGS = -Wall -Wextra -Werror

OBJ = $(SRCS:.c=.o)

all: $(NAME)

$(NAME) : $(OBJ)
	make -C libft
	gcc $(CFLAGS) $(OBJ) libft/libft.a -o $(NAME) -lm

clean :
	make -C libft clean
	rm -f *.o

fclean :
	make -C libft fclean
	rm -f *.o
	rm ft_ping

re :
	make fclean
	make
