CC = gcc
INCLUDE := -I../include
LDFLAGS := -L../lib
LDLIBS  := -ltlp -lpthread
CFLAGS  := -g -Wall $(INCLUDE)

# PROGNAME = dma_read dma_write psmem process-list_upa pgd-walk codedump \
# 	   tlpperf pcie_cfg_read pcie_cfg_write \
# 	   dump_mem find_swapper0 phys_addrs_from_mem_map process-list calc_init_task_addr

PROGNAME = dma_read dma_write dump_mem

all: $(PROGNAME)

.c.o: util.h
	$(CC) $< -o $@

clean:
	rm -rf *.o
	rm -rf $(PROGNAME)
	rm -rf *.dSYM
