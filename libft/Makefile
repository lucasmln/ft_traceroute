# **************************************************************************** #
#                                                                              #
#                                                         :::      ::::::::    #
#    Makefile                                           :+:      :+:    :+:    #
#                                                     +:+ +:+         +:+      #
#    By: jgrandne <marvin@42.fr>                    +#+  +:+       +#+         #
#                                                 +#+#+#+#+#+   +#+            #
#    Created: 2019/10/16 11:50:11 by jgrandne          #+#    #+#              #
#    Updated: 2019/10/17 11:25:59 by lmoulin          ###   ########.fr        #
#                                                                              #
# **************************************************************************** #

NAME = libft.a

SRCS = ft_atoi.c ft_isascii.c ft_isalpha.c \
ft_tolower.c ft_strlcat.c ft_strlen.c \
ft_strnstr.c ft_toupper.c ft_isalnum.c ft_isdigit.c \
ft_isprint.c ft_strchr.c  ft_strlcpy.c ft_strncmp.c \
ft_strrchr.c ft_memset.c ft_bzero.c ft_memcpy.c \
ft_memccpy.c ft_memmove.c ft_memchr.c ft_memcmp.c \
ft_strdup.c ft_calloc.c ft_itoa.c ft_substr.c \
ft_strtrim.c ft_putchar_fd.c ft_putstr_fd.c \
ft_putendl_fd.c ft_putnbr_fd.c ft_strmapi.c ft_split.c ft_strjoin.c

SRCS_BONUS_LIBFT = ft_lstnew_bonus.c ft_lstadd_front_bonus.c \
ft_lstsize_bonus.c ft_lstlast_bonus.c \
ft_lstadd_back_bonus.c ft_lstdelone_bonus.c \
ft_lstclear_bonus.c ft_lstiter_bonus.c \
ft_lstmap_bonus.c

INCLUDES = libft.h
OBJS_LIBFT = $(SRCS:.c=.o)
OBJS_BONUS_LIBFT = $(SRCS_BONUS_LIBFT:.c=.o)

CC = gcc

CFLAGS = -Wall -Wextra -Werror

# Text format
_DEF = $'\033[0m
_END = $'\033[0m
_GRAS = $'\033[1m
_SOUL = $'\033[4m
_CLIG = $'\033[5m
_SURL = $'\033[7m

# Colors
_BLACK = $'\033[30m
_RED = $'\033[31m
_GREEN = $'\033[32m
_YELLOW = $'\033[33m
_BLUE = $'\033[34m
_PURPLE = $'\033[35m
_CYAN = $'\033[36m
_GREY = $'\033[37m

# Background
_IBLACK = $'\033[40m
_IRED = $'\033[41m
_IGREEN = $'\033[42m
_IYELLOW = $'\033[43m
_IBLUE = $'\033[44m
_IPURPLE = $'\033[45m
_ICYAN = $'\033[46m
_IGREY = $'\033[47m

all : $(NAME)

$(NAME) : $(OBJS_LIBFT)
	@echo "$(_END)$(_GREEN) [OK]\t"
	@ar rc $(NAME) $(OBJS_LIBFT)
	@ranlib $(NAME)
	@echo "$(_END)$(_GREEN)[Done]"

%.o : %.c $(INCLUDES)
	@echo "$(_END)$(_GREEN) [OK]\t"
	@$(CC) $(CFLAGS) -I $(INCLUDES) -o ${<:.c=.o} -c $<
re : 
	@make fclean 
	@make all
	
bonus : $(OBJS_LIBFT) $(OBJS_BONUS_LIBFT)
	@echo "$(_END)$(_YELLOW) [COMPILE WITH BONUS FUNCTION]\t"
	@ar rc $(NAME) $(OBJS_LIBFT) $(OBJS_BONUS_LIBFT)
	@ranlib $(NAME)
	@echo "$(_GREEN) [OK]"
	@echo "$(_END)$(_YELLOW)[Done]"


fclean : clean
	@rm -f $(NAME)

clean :
	@rm -f $(OBJS_LIBFT) $(OBJS_BONUS_LIBFT)

.PHONY : all re fclean clean bonus
