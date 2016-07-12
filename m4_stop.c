/*
 * m4_stop.c operations to force secure exit M4 sketch
 *
 * Copyright (C) 2015-2016 Giuseppe Pagano <giuseppe.pagano@seco.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <ctype.h>
#include <termios.h>
#include <sys/types.h>
#include <sys/mman.h>
  
#define MAP_SIZE 4096UL
#define MAP_MASK (MAP_SIZE - 1)

#define VERSION "M4_stop 1.0.0"

#define ADDR_SHARED_BYTE_FOR_M4STOP		0xbff0ffff	// to force M4 scketch to secure exit


void send_m4_flag(int fd, unsigned char value) {
	off_t target;
	void *map_base, *virt_addr;

	target = ADDR_SHARED_BYTE_FOR_M4STOP;
	map_base = mmap(0, MAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd,
			target & ~MAP_MASK);
	virt_addr = map_base + (target & MAP_MASK);
	*((unsigned char *) virt_addr) = value;
	munmap(map_base, MAP_SIZE);
}


int main(void) {
	int fd;

	printf ("\n%s\n", VERSION);
	fd = open("/dev/mem", O_RDWR | O_SYNC);
	printf ("send 0xAA\n");
	send_m4_flag(fd, 0xAA);
	sleep(1);
	printf ("send 0x00\n");
	send_m4_flag(fd, 0x00);
	close(fd);
	printf ("reset m4 flag done !\n");
	return 0;
}

