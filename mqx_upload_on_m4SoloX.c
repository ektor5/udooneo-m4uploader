/*
 * mqx_upload_on_m4SoloX.c operations to load fw and startup M4 core
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

#define SIZE_4BYTE 4UL
#define SIZE_16BYTE 16UL
#define SIZE_4KBYTE 4096UL

#define MAP_OCRAM_SIZE 512*1024
#define MAP_OCRAM_MASK (MAP_OCRAM_SIZE - 1)

#define MAX_FILE_SIZE MAP_OCRAM_SIZE

#define SRC_SCR 0x020d8000
#define M4c_CL_RST (1 << 3)
#define M4c_RST (1 << 4)
#define M4p_CL_RST (1 << 12)
#define M4_ENABLE (1 << 22)

#define STACK_PC 0x007F8000

#define RDC_BASE 0x020FC000
#define RDC_MDA_BASE 0x200
#define RDC_MDA1     0x204
#define RDC_PDA_BASE 0x400
#define RDC_MR_BASE  0x800
#define RDC_MR_MRC1  0x808
#define RDC_MR_MRVS1 0x80C

#define AIPS1_BASE 0x0207C000
#define AIPS2_BASE 0x0217C000
#define AIPS3_BASE 0x0227C000

void set_gate_m4_clk(int fd) {
	off_t target;
	unsigned long read_result;
	void *map_base, *virt_addr;

        target = 0x020c4074;
        map_base = mmap(0, MAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, target & ~MAP_MASK);
        virt_addr = map_base + (target & MAP_MASK);
        read_result = *((unsigned long *) virt_addr);
        *((unsigned long *) virt_addr) = read_result | 0x0000000C;
        munmap(map_base, MAP_SIZE);
}

void srcscr_set_bit(int fd, unsigned int set_mask) {
	void *virt_addr; 
	unsigned long read_result;
	virt_addr = mmap(0, SIZE_4BYTE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, (off_t) SRC_SCR);
	read_result = *((unsigned long *) virt_addr);
	*((unsigned long *) virt_addr) = read_result | set_mask;
	munmap(virt_addr, SIZE_4BYTE);
}

void srcscr_unset_bit(int fd, unsigned int unset_mask) {
	void *virt_addr; 
	unsigned long read_result;
	virt_addr = mmap(0, SIZE_4BYTE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, (off_t) SRC_SCR);
	read_result = *((unsigned long *) virt_addr);
	*((unsigned long *) virt_addr) = read_result & unset_mask;
	munmap(virt_addr, SIZE_4BYTE);
}

void set_stack_pc(int fd, unsigned int stack, unsigned int pc) {
	off_t target = (off_t) STACK_PC;
	unsigned long read_result;
	void *map_base, *virt_addr; 
	map_base = mmap(0, SIZE_16BYTE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, (off_t) target);
	virt_addr = map_base + (target & MAP_MASK);
	*((unsigned long *) virt_addr) = stack;
	virt_addr = map_base + ((target + 0x4) & MAP_MASK);
	*((unsigned long *) virt_addr) = pc;
	munmap(map_base, SIZE_16BYTE);
}

void rdc_reset(int fd) {
	int n;
	void *map_base, *virt_addr; 
	off_t target;

	target = (off_t) RDC_BASE;
	map_base = mmap(0, SIZE_4KBYTE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, target);

	virt_addr = map_base + RDC_MR_MRC1;
	*((unsigned long *) virt_addr) = 0xff;
	virt_addr = map_base + RDC_MR_MRVS1;
	*((unsigned long *) virt_addr) = 0x0;

	for (n=0; n<110; n++) {
		virt_addr = map_base + RDC_PDA_BASE + (n*0x4);
		*((unsigned long *) virt_addr) = 0xFF;
	}

	virt_addr = map_base + RDC_MDA1;
	*((unsigned long *) virt_addr) = 0x0;

	munmap(map_base, SIZE_4KBYTE);
}


void aips123_reset(int fd) {
	void *virt_addr; 
	unsigned long read_result;

	virt_addr = mmap(0, SIZE_4BYTE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, (off_t) AIPS1_BASE);
	read_result = *((unsigned long *) virt_addr);
	*((unsigned long *) virt_addr) = 0x77777777;
	munmap(virt_addr, SIZE_4BYTE);

	virt_addr = mmap(0, SIZE_4BYTE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, (off_t) AIPS2_BASE);
	read_result = *((unsigned long *) virt_addr);
	*((unsigned long *) virt_addr) = 0x77777777;
	munmap(virt_addr, SIZE_4BYTE);

	virt_addr = mmap(0, SIZE_4BYTE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, (off_t) AIPS3_BASE);
	read_result = *((unsigned long *) virt_addr);
	*((unsigned long *) virt_addr) = 0x77777777;
	munmap(virt_addr, SIZE_4BYTE);
}

int load_m4_fw(int fd, char *filepath, unsigned int loadaddr) {
	int n;
	int size;
	FILE *fdf;
	off_t target;
	char *filebuffer;
	void *map_base, *virt_addr; 
	unsigned long stack, pc;

	fdf = fopen(filepath, "rb");
	fseek(fdf, 0, SEEK_END);
	size = ftell(fdf);
	fseek(fdf, 0, SEEK_SET);
	if (size > MAX_FILE_SIZE) {
		printf("File size too big, can't load: %d > %d \n", size, MAX_FILE_SIZE);
		return -2; 
	}
	filebuffer = (char *)malloc(size+1);
	if (size != fread(filebuffer, sizeof(char), size, fdf)) { 
		free(filebuffer);
		return -2; 
	} 

	fclose(fdf);

	stack = (filebuffer[0] | (filebuffer[1] << 8) | (filebuffer[2] << 16) | (filebuffer[3] << 24));
	pc = (filebuffer[4] | (filebuffer[5] << 8) | (filebuffer[6] << 16) | (filebuffer[7] << 24));

	if (loadaddr == 0x0) {
		loadaddr = pc & 0xFFFF0000;
	}
	printf("FILENAME = %s; loadaddr = 0x%08x\n", filepath, loadaddr);

	map_base = mmap(0, MAP_OCRAM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, loadaddr & ~MAP_OCRAM_MASK);
printf("start - end (0x%08x - 0x%08x)\n", loadaddr & ~MAP_OCRAM_MASK, (loadaddr & ~MAP_OCRAM_MASK) + MAP_OCRAM_SIZE);
	virt_addr = map_base + (loadaddr & MAP_OCRAM_MASK);
	memcpy(virt_addr, filebuffer, size);
	munmap(map_base, MAP_OCRAM_SIZE);

	set_stack_pc(fd, stack, pc);
	free(filebuffer);

	return size; 
}

int main(int argc, char **argv) {
	int fd, n, size, size2;
	int update_fw = 1;
	void *map_base, *virt_addr; 
	unsigned long stack, pc, loadaddr;
	unsigned long read_result, writeval;
	off_t target;
	char *p;

	char *filepath;
	filepath = (char *)malloc(150);

	if (argc < 2) {
		printf("\n\tUsage: %s <project_name> [0xLOADADDR]\n\n", argv[0]);
		return 1;
	}
		
	sprintf(filepath, "%s", argv[1]);

	if (argc == 3) {
		loadaddr = strtoul(argv[2], &p, 16);
	} else {
//		printf("Warn ! Missing LOADADDR. Not loading new fw in to DDR ram.\n");
//		update_fw = 0;

		loadaddr = 0x0;
	} 
	
	fd = open("/dev/mem", O_RDWR | O_SYNC);

	if (update_fw == 1) {
		srcscr_set_bit(fd, (M4c_RST));
//		rdc_reset(fd);
//		aips123_reset(fd);
		set_gate_m4_clk(fd);
		load_m4_fw(fd, filepath, loadaddr);
	}
	free(filepath);

//	srcscr_set_bit(fd, M4_ENABLE);
//	srcscr_set_bit(fd, (M4_ENABLE | M4c_CL_RST | M4p_CL_RST));
//	srcscr_set_bit(fd, (M4_ENABLE | M4p_CL_RST));
//	srcscr_set_bit(fd, (M4_ENABLE | M4c_RST));

	srcscr_unset_bit(fd, ~(M4c_RST));
        sleep(0.1);
	srcscr_set_bit(fd, M4c_CL_RST);

        close(fd);
        return 0;
}
