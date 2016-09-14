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
  
#define VERSION	"mqx_upload_on_m4SoloX 1.1.0"
#define NAME_OF_BOARD			"UDOONeo"

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

#define ADDR_SHARED_TRACE_FLAGS			0xbff0fff4		// address shared RAM for M4 trace flags
#define ADDR_SHARED_BYTE_FOR_M4STOP 	0xbff0ffff		// to force M4 sketch to secure exit
#define MSK1_SHARED_TRACE_FLAGS			0x00000001		// toolchain_startup
#define MSK2_SHARED_TRACE_FLAGS			0x00000002		// main
#define MSK3_SHARED_TRACE_FLAGS			0x00000004		// _mqx
#define MSK4_SHARED_TRACE_FLAGS			0x00000008		// _bsp_pre_init
#define MSK5_SHARED_TRACE_FLAGS			0x00000010		// _bsp_init
#define MSK6_SHARED_TRACE_FLAGS			0x00000020		// main_task is running
#define MSK7_SHARED_TRACE_FLAGS			0x00000040		// exit_task is running
#define MSK8_SHARED_TRACE_FLAGS			0x00000080		// arduino_loop_task is running
#define MSK9_SHARED_TRACE_FLAGS			0x00000100		// arduino_yield_task is running
#define MSK10_SHARED_TRACE_FLAGS		0x00000200		// mqx_mccuart_receive_task is running
#define MSK11_SHARED_TRACE_FLAGS		0x00000400		// mqx_uart_receive_task is running
#define MSK12_SHARED_TRACE_FLAGS		0x00000800		// _mqx_exit

#define RETURN_CODE_OK					0
#define RETURN_CODE_ARGUMENTS_ERROR		1
#define RETURN_CODE_M4STOP_FAILED		2
#define RETURN_CODE_M4START_FAILED		3

void send_m4_stop_flag(int fd, unsigned char value) {
	off_t target;
	void *map_base, *virt_addr;

    target = ADDR_SHARED_BYTE_FOR_M4STOP;
    map_base = mmap(0, MAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, target & ~MAP_MASK);
    virt_addr = (unsigned char *)map_base + (target & MAP_MASK);
    *((unsigned char *) virt_addr) = value;
    munmap(map_base, MAP_SIZE);
}

void reset_m4_trace_flag(int fd) {
	off_t target;
	void *map_base, *virt_addr;

    target = ADDR_SHARED_TRACE_FLAGS;
    map_base = mmap(0, MAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, target & ~MAP_MASK);
    virt_addr = (unsigned char *)map_base + (target & MAP_MASK);
    *((int *) virt_addr) = 0L;
    munmap(map_base, MAP_SIZE);
}

int get_m4_trace_flag(int fd) {
	off_t target;
	void *map_base, *virt_addr;
	int value;

    target = ADDR_SHARED_TRACE_FLAGS;
    map_base = mmap(0, MAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, target & ~MAP_MASK);
    virt_addr = (unsigned char *)map_base + (target & MAP_MASK);
    value = *((int *) virt_addr);
    munmap(map_base, MAP_SIZE);
	return (value);
}

void set_gate_m4_clk(int fd) {
	off_t target;
	unsigned long read_result;
	void *map_base, *virt_addr;

        target = 0x020c4074;
        map_base = mmap(0, MAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, target & ~MAP_MASK);
        virt_addr = (unsigned char *)map_base + (target & MAP_MASK);
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
	virt_addr = (unsigned char *)map_base + (target & MAP_MASK);
	*((unsigned long *) virt_addr) = stack;
	virt_addr = (unsigned char *)map_base + ((target + 0x4) & MAP_MASK);
	*((unsigned long *) virt_addr) = pc;
	munmap(map_base, SIZE_16BYTE);
}

void rdc_reset(int fd) {
	int n;
	void *map_base, *virt_addr;
	off_t target;

	target = (off_t) RDC_BASE;
	map_base = mmap(0, SIZE_4KBYTE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, target);

	virt_addr = (unsigned char *)map_base + RDC_MR_MRC1;
	*((unsigned long *) virt_addr) = 0xff;
	virt_addr = (unsigned char *)map_base + RDC_MR_MRVS1;
	*((unsigned long *) virt_addr) = 0x0;

	for (n=0; n<110; n++) {
		virt_addr = (unsigned char *)map_base + RDC_PDA_BASE + (n*0x4);
		*((unsigned long *) virt_addr) = 0xFF;
	}

	virt_addr = (unsigned char *)map_base + RDC_MDA1;
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
		printf("%s - File size too big, can't load: %d > %d \n", NAME_OF_BOARD, size, MAX_FILE_SIZE);
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
	printf("%s - FILENAME = %s; loadaddr = 0x%08x\n", NAME_OF_BOARD, filepath, loadaddr);

	map_base = mmap(0, MAP_OCRAM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, loadaddr & ~MAP_OCRAM_MASK);
	printf("%s - start - end (0x%08x - 0x%08x)\n", NAME_OF_BOARD, loadaddr & ~MAP_OCRAM_MASK, (loadaddr & ~MAP_OCRAM_MASK) + MAP_OCRAM_SIZE);
	virt_addr = (unsigned char *)map_base + (loadaddr & MAP_OCRAM_MASK);
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
	char m4IsStopped = 0;
	char m4IsRunning = 0;
	int m4TraceFlags=0;
	int m4Retry;

	printf ("\n%s - %s\n", NAME_OF_BOARD, VERSION);

	char *filepath;
	filepath = (char *)malloc(150);

	if (argc < 2) {
		fprintf(stderr, "\n\t%s - Usage: %s <project_name> [0xLOADADDR]\n\n", NAME_OF_BOARD, argv[0]);
		return (RETURN_CODE_ARGUMENTS_ERROR);
	}

	sprintf(filepath, "%s", argv[1]);

	if(access(filepath, F_OK) == -1) {
		fprintf(stderr, "\n\tFile %s not found.\n", argv[1]);
                return RETURN_CODE_ARGUMENTS_ERROR;
	}

	if (argc == 3) {
		loadaddr = strtoul(argv[2], &p, 16);
	} else {
//		printf("Warn ! Missing LOADADDR. Not loading new fw in to DDR ram.\n");
//		update_fw = 0;

		loadaddr = 0x0;
	} 
	
	fd = open("/dev/mem", O_RDWR | O_SYNC);

	// ======================================================================
	// check if sketch is running
	// ======================================================================
	if (get_m4_trace_flag(fd) != 0) {
		reset_m4_trace_flag(fd);
		// do stop M4 sketch command
		send_m4_stop_flag(fd, 0xAA);		//(replace m4_stop tool function)
		m4Retry=4;
		while ((m4IsStopped == 0) && (m4Retry>0)){
			usleep(300000);
			m4Retry--;
			m4TraceFlags = get_m4_trace_flag(fd);
			printf ("%s - Waiting M4 Stop, m4TraceFlags: %08X \n", NAME_OF_BOARD, m4TraceFlags);
			if((m4TraceFlags & MSK12_SHARED_TRACE_FLAGS) != 0) {
				m4IsStopped = 1;
				printf ("%s - Stopped M4 sketch \n",NAME_OF_BOARD);
			}
		}
		send_m4_stop_flag(fd, 0x00);
		if (m4IsStopped == 0) {
			fprintf (stderr, "%s - Failed to Stop M4 sketch: reboot system ! \n",NAME_OF_BOARD);
		    close(fd);
			exit (RETURN_CODE_M4STOP_FAILED);
		}
		usleep(300000);	// for execute _mqx_exit 
	}
	// ======================================================================
	// end check if sketch is running
	// ======================================================================

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
//	srcscr_set_bit(fd, M4c_CL_RST);

	// ======================================================================
	// check if sketch is running
	// ======================================================================
	m4Retry=4;
	while ((m4IsRunning == 0) && (m4Retry>0)){
		usleep(300000); 
		m4Retry--;
		m4TraceFlags = get_m4_trace_flag(fd);
		printf ("%s - Waiting M4 Run, m4TraceFlags: %08X \n", NAME_OF_BOARD, m4TraceFlags);
		if((m4TraceFlags & (MSK6_SHARED_TRACE_FLAGS | MSK7_SHARED_TRACE_FLAGS | MSK8_SHARED_TRACE_FLAGS | MSK9_SHARED_TRACE_FLAGS)) == 
			(MSK6_SHARED_TRACE_FLAGS | MSK7_SHARED_TRACE_FLAGS | MSK8_SHARED_TRACE_FLAGS | MSK9_SHARED_TRACE_FLAGS)) {
			m4IsRunning = 1;
			printf ("%s - M4 sketch is running\n", NAME_OF_BOARD);
		}
	}
	if (m4IsRunning == 0) {
		fprintf (stderr, "%s - Failed to Start M4 sketch: reboot system ! \n", NAME_OF_BOARD);
	    close(fd);
		exit (RETURN_CODE_M4START_FAILED);
	}
	// ======================================================================
	// end check if sketch is running
	// ======================================================================

	close(fd);
	exit (RETURN_CODE_OK);
}

