// Simple command-line kernel monitor useful for
// controlling the kernel and exploring the system interactively.

#include <inc/stdio.h>
#include <inc/string.h>
#include <inc/memlayout.h>
#include <inc/assert.h>
#include <inc/x86.h>

#include <kern/console.h>
#include <kern/monitor.h>
#include <kern/kdebug.h>
#include <kern/pmap.h>

#define CMDBUF_SIZE 80 // enough for one VGA text line

struct Command
{
    const char *name;
    const char *desc;
    // return -1 to force monitor to exit
    int (*func)(int argc, char **argv, struct Trapframe *tf);
};

static struct Command commands[] = {
    {"help", "Display this list of commands", mon_help},
    {"kerninfo", "Display information about the kernel", mon_kerninfo},
    {"backtrace", "Display the stack backtrace", mon_backtrace},
    {"vaddrinfo", "Display information about virtual address", mon_vaddrinfo},
    {"pgdir", "Display the contents of a page directory or a page table", mon_pgdir},
    {"vmmap", "Display virtual memory map", mon_vmmap}};

/***** Implementations of basic kernel monitor commands *****/

int mon_help(int argc, char **argv, struct Trapframe *tf)
{
    int i;

    for (i = 0; i < ARRAY_SIZE(commands); i++)
        cprintf("%s - %s\n", commands[i].name, commands[i].desc);
    return 0;
}

int mon_kerninfo(int argc, char **argv, struct Trapframe *tf)
{
    extern char _start[], entry[], etext[], edata[], end[];

    cprintf("Special kernel symbols:\n");
    cprintf("  _start                  %08x (phys)\n", _start);
    cprintf("  entry  %08x (virt)  %08x (phys)\n", entry, entry - KERNBASE);
    cprintf("  etext  %08x (virt)  %08x (phys)\n", etext, etext - KERNBASE);
    cprintf("  edata  %08x (virt)  %08x (phys)\n", edata, edata - KERNBASE);
    cprintf("  end    %08x (virt)  %08x (phys)\n", end, end - KERNBASE);
    cprintf("Kernel executable memory footprint: %dKB\n",
            ROUNDUP(end - entry, 1024) / 1024);
    return 0;
}

int mon_backtrace(int argc, char **argv, struct Trapframe *tf)
{
    uint32_t ebp;
    struct Eipdebuginfo info;
    __asm__ __volatile__("movl %%ebp,%0" : "=r"(ebp));

    cprintf("Stack backtrace:\n");

    while (ebp != 0)
    {
        uint32_t eip = *((uint32_t *)ebp + 1);
        cprintf("ebp %08x eip %08x args", ebp, eip);

        for (int i = 2; i < 7; i++)
        {
            cprintf(" %08x", *((uint32_t *)ebp + i));
        }
        cprintf("\n");

        debuginfo_eip(eip, &info);
        uintptr_t offset = eip - info.eip_fn_addr;
        cprintf("      %s:%d: ", info.eip_file, info.eip_line);
        cprintf("%.*s+%d\n", info.eip_fn_namelen, info.eip_fn_name, offset);

        ebp = *(uint32_t *)ebp;
    }

    return 0;
}

// Attempts to match prefix to s. If found, returns the index after the prefix
// or a NULL if prefix not found.
const char *
prefix_find(const char *s, const char *prefix)
{
    for (; *s && *prefix; s++, prefix++)
    {
        if (*s != *prefix)
            return NULL;
    }
    return s;
}

/**
 * extract_hex_addr - Parse a hexadecimal address string into a uintptr_t
 *
 * This function extracts a hexadecimal address from a string, handling both
 * "0x" prefixed and non-prefixed formats. It performs validation to ensure
 * the address is within valid bounds for a 32-bit system.
 *
 * @address: Pointer to store the parsed address (output parameter)
 * @s: Input string containing the hexadecimal address
 *
 * The function:
 * 1. Attempts to remove "0x" prefix if present using prefix_find()
 * 2. Validates the address string length (max 8 hex digits for 32-bit)
 * 3. Converts the string to a long using strtol() with base 16
 * 4. Validates that the entire string was consumed (no trailing characters)
 * 5. Stores the result in the provided address pointer
 *
 * @return: 0 on success, -1 on error (invalid format or too long)
 */
int extract_hex_addr(uintptr_t *address, const char *s)
{
    const char *removed_prefix = prefix_find(s, "0x");
    const char *addr_str = removed_prefix ? removed_prefix : s;
    if (strlen(addr_str) > 8)
    {
        return -1;
    }
    char *endptr = NULL;
    long addr = strtol(addr_str, &endptr, 16);
    if (!endptr || *endptr != '\0')
    {
        return -1;
    }
    assert(address);
    *address = (uintptr_t)addr;
    return 0;
}

/**
 * print_pagetable_entry - Display formatted information about a page table entry
 *
 * This function prints detailed information about a specific page table entry,
 * including its offset, physical address, and permission flags. It's used by
 * both page directory and page table analysis functions.
 *
 * @pte_table: Pointer to the page table (or page directory) containing the entry
 * @offset: Index of the entry within the table (0-1023 for standard tables)
 *
 * Output format: "XXX: YYYYYYYY FLAGS"
 * - XXX: 3-digit hex offset of the entry in the table
 * - YYYYYYYY: 8-digit hex physical address (page-aligned, lower 12 bits cleared)
 * - FLAGS: Space-separated list of present permission flags
 *
 * Permission flags displayed:
 * - PTE_P: Page is present in memory
 * - PTE_W: Page is writable
 * - PTE_U: Page is accessible from user mode
 * - NONE: Displayed when no permission bits are set (bits 0-8 all clear)
 */
void print_pagetable_entry(pte_t *pte_table, int offset)
{
    pte_t pte = pte_table[offset];
    cprintf("%03x: %08x ", offset, PTE_ADDR(pte));
    if ((pte & 0x1ff) == 0)
    {
        cprintf("NONE\n");
        return;
    }
    if (pte & PTE_P)
        cprintf("PTE_P ");
    if (pte & PTE_W)
        cprintf("PTE_W ");
    if (pte & PTE_U)
        cprintf("PTE_U ");

    cprintf("\n");
}

/**
 * mon_vaddrinfo - Monitor command to display virtual address translation information
 *
 * This function implements the "vaddrinfo" monitor command, which provides detailed
 * information about how a virtual address is translated to a physical address
 * through the page directory and page table hierarchy. It's useful for debugging
 * memory management and understanding the paging mechanism.
 *
 * @argc: Number of command arguments (must be 2: command + address)
 * @argv: Command arguments array, where argv[1] is the virtual address
 * @tf: Trap frame (unused in this function)
 *
 * The function performs a complete page table walk:
 * 1. Parses the input virtual address from argv[1]
 * 2. Gets the current page directory from CR3 register
 * 3. Extracts page directory index (PDX) from the virtual address
 * 4. Displays page directory entry information and permissions
 * 5. If PDE is present, follows the pointer to the page table
 * 6. Extracts page table index (PTX) from the virtual address
 * 7. Displays page table entry information and permissions
 * 8. If PTE is present, calculates final physical address
 *
 * Output includes:
 * - Page-aligned virtual address
 * - Page directory virtual address and relevant entry
 * - Page table virtual address and relevant entry
 * - Final page frame address and complete physical address
 *
 * @return: 0 on success
 */
int mon_vaddrinfo(int argc, char **argv, struct Trapframe *tf)
{
    if (argc != 2)
    {
        cprintf("usage: vaddr <virtual address>\n");
        return 0;
    }
    uintptr_t address;
    if (extract_hex_addr(&address, argv[1]) < 0)
    {
        cprintf("invalid address entered: %s\n", argv[1]);
        return 0;
    }
    uintptr_t page = ROUNDDOWN(address, PGSIZE);
    pde_t *pgdir = KADDR(rcr3());
    cprintf("Page virtual address:\t\t%08x\n", page);
    cprintf("Page dir virtual address:\t%08x\t", pgdir);
    int pdoffset = PDX(address);
    print_pagetable_entry(pgdir, pdoffset);

    pde_t pde = pgdir[pdoffset];
    if (!(pde & PTE_P))
    {
        cprintf("Address not found in page directory\n");
        return 0;
    }
    pte_t *pagetable = KADDR(PTE_ADDR(pde));
    cprintf("Page table virtual address:\t%08x\t", pagetable);
    int ptoffset = PTX(address);
    print_pagetable_entry(pagetable, ptoffset);

    pte_t pte = pagetable[ptoffset];
    if (!(pte & PTE_P))
    {
        cprintf("Address not found in page table\n");
        return 0;
    }
    cprintf("Page frame address:\t\t%08x\n", PTE_ADDR(pte));
    cprintf("Physical address:\t\t%08x\n", PTE_ADDR(pte) + PGOFF(address));
    return 0;
}

/**
 * mon_pgdir - Monitor command to display page directory or page table contents
 *
 * This function implements the "pgdir" monitor command, which allows examination
 * of page directory and page table structures. It can display single entries,
 * ranges of entries, or entire tables, making it useful for debugging memory
 * management and understanding page table organization.
 *
 * @argc: Number of command arguments (2-4 supported)
 * @argv: Command arguments array:
 *        argv[1] = page directory/table address (must be page-aligned)
 *        argv[2] = single offset OR begin offset (optional)
 *        argv[3] = end offset (optional, requires argv[2])
 * @tf: Trap frame (unused in this function)
 *
 * Usage modes:
 * 1. pgdir <address>                 - Display all entries (0 to NPTENTRIES-1)
 * 2. pgdir <address> <offset>        - Display single entry at offset
 * 3. pgdir <address> <begin> <end>   - Display range of entries
 *
 * The function performs several validations:
 * - Address must be properly formatted hexadecimal
 * - Address must be page-aligned (multiple of PGSIZE)
 * - Address must be mapped in the current page directory
 * - Offset values must be within valid range (0 to NPTENTRIES-1)
 * - Begin offset must be <= end offset
 *
 * For each entry in the specified range, it calls print_pagetable_entry()
 * to display the offset, physical address, and permission flags.
 *
 * @return: 0 on success
 */
int mon_pgdir(int argc, char **argv, struct Trapframe *tf)
{
    if (argc < 2 || argc > 4)
    {
        cprintf("usage: pgdir <address>\n");
        cprintf("       pgdir <address> <offset>\n");
        cprintf("       pgdir <address> <begin offset> <end offset>\n");
        return 0;
    }

    uintptr_t address;
    if (extract_hex_addr(&address, argv[1]) < 0)
    {
        cprintf("invalid address %s\n", argv[1]);
        return 0;
    }
    else if (address % PGSIZE != 0)
    {
        cprintf("Address of pgdir must be paged aligned.\n");
        return 0;
    }
    else if (!page_lookup((void *)KADDR(rcr3()), (void *)address, NULL))
    {
        cprintf("Virtual address %x is not mapped.\n", address);
        return 0;
    }

    uint16_t begin, end;
    if (argc == 2)
    {
        begin = 0;
        end = NPTENTRIES - 1;
    }
    else if (argc == 3)
    {
        begin = end = (uint16_t)strtol(argv[2], NULL, 16);
    }
    else if (argc == 4)
    {
        begin = (uint16_t)strtol(argv[2], NULL, 16);
        end = (uint16_t)strtol(argv[3], NULL, 16);
    }
    if (begin > end || end >= NPTENTRIES)
    {
        cprintf("invalid offset(s): begin should be <= end, and\n");
        cprintf("offset(s) should be between 0 and %x\n", NPTENTRIES - 1);
        return 0;
    }
    for (int i = begin; i <= end; i++)
    {
        print_pagetable_entry((pte_t *)address, i);
    }
    return 0;
}

/**
 * mon_vmmap - Display comprehensive virtual memory mapping information
 *
 * This function provides a detailed view of the JOS kernel's virtual memory layout,
 * including predefined memory regions, kernel symbols, page directory analysis,
 * and memory usage statistics. It's designed to help understand how virtual
 * addresses are organized and mapped in the JOS operating system.
 *
 * @argc: Number of command arguments (should be 1 for vmmap)
 * @argv: Command arguments array
 * @tf: Trap frame (unused in this function)
 * @return: 0 on success
 */
int mon_vmmap(int argc, char **argv, struct Trapframe *tf)
{
    /* Validate command usage - vmmap takes no additional arguments */
    if (argc != 1)
    {
        cprintf("usage: vmmap\n");
        return 0;
    }

    /*
     * Get kernel symbol addresses defined by the linker script.
     * These symbols mark important boundaries in the kernel's memory layout:
     * - _start: Very beginning of kernel image
     * - entry: Kernel entry point
     * - etext: End of kernel code section
     * - edata: End of kernel initialized data
     * - end: End of kernel image (including BSS)
     */
    extern char _start[], entry[], etext[], edata[], end[];

    /*
     * Get the current page directory from CR3 register.
     * CR3 contains the physical address of the page directory,
     * so we convert it to a kernel virtual address using KADDR()
     */
    pde_t *pgdir = KADDR(rcr3());

    /* ========== SECTION 1: VIRTUAL MEMORY LAYOUT ========== */
    cprintf("Virtual Memory Map:\n");
    cprintf("===================\n\n");

    /*
     * Define the standard JOS virtual memory regions.
     * This array describes the canonical memory layout as defined in memlayout.h
     * Each region has start/end addresses, descriptive name, and permission info.
     * Permissions format: "kernel_perms/user_perms" where:
     * - R = Read, W = Write, -- = No access
     */
    struct
    {
        uintptr_t start;         /* Virtual address where region starts */
        uintptr_t end;           /* Virtual address where region ends */
        const char *name;        /* Human-readable description */
        const char *permissions; /* Access permissions (kernel/user) */
    } regions[] = {
        /* Kernel-only regions (above KERNBASE = 0xF0000000) */
        {KERNBASE, 0xFFFFFFFF, "Remapped Physical Memory", "RW/--"},
        {KSTACKTOP - KSTKSIZE, KSTACKTOP, "CPU0 Kernel Stack", "RW/--"},
        {MMIOBASE, MMIOLIM, "Memory-mapped I/O", "RW/--"},

        /* User-accessible regions (below ULIM) */
        {UVPT, UVPT + PTSIZE, "User Page Table (Read-only)", "R-/R-"},
        {UPAGES, UPAGES + PTSIZE, "Read-only Pages Info", "R-/R-"},
        {UENVS, UENVS + PTSIZE, "Read-only Environments", "R-/R-"},
        {UXSTACKTOP - PGSIZE, UXSTACKTOP, "User Exception Stack", "RW/RW"},
        {USTACKTOP, USTACKTOP + PGSIZE, "Normal User Stack", "RW/RW"},
        {UTEXT, USTACKTOP, "Program Data & Heap", "RW/RW"},
        {(uintptr_t)UTEMP, (uintptr_t)UTEMP + PTSIZE, "Temporary Mappings", "--/--"},
        {USTABDATA, USTABDATA + PTSIZE / 2, "User STAB Data", "--/--"},
        {0, USTABDATA, "Empty Memory", "--/--"}};

    /*
     * Display each memory region in a formatted table.
     * Shows start/end addresses, size in KB, name, and permissions.
     */
    for (int i = 0; i < sizeof(regions) / sizeof(regions[0]); i++)
    {
        cprintf("0x%08x - 0x%08x  %8dKB  %-25s  %s\n",
                regions[i].start,
                regions[i].end,
                (regions[i].end - regions[i].start) / 1024,
                regions[i].name,
                regions[i].permissions);
    }

    /* ========== SECTION 2: KERNEL SYMBOL INFORMATION ========== */
    cprintf("\nKernel Symbol Information:\n");
    cprintf("==========================\n");
    /*
     * Display important kernel symbols and their addresses.
     * Shows both virtual and physical addresses for kernel symbols.
     * Physical address = Virtual address - KERNBASE for kernel addresses.
     */
    cprintf("_start: 0x%08x (phys)\n", (uintptr_t)_start);
    cprintf("entry:  0x%08x (virt)  0x%08x (phys)\n", (uintptr_t)entry, (uintptr_t)entry - KERNBASE);
    cprintf("etext:  0x%08x (virt)  0x%08x (phys)\n", (uintptr_t)etext, (uintptr_t)etext - KERNBASE);
    cprintf("edata:  0x%08x (virt)  0x%08x (phys)\n", (uintptr_t)edata, (uintptr_t)edata - KERNBASE);
    cprintf("end:    0x%08x (virt)  0x%08x (phys)\n", (uintptr_t)end, (uintptr_t)end - KERNBASE);

    /* ========== SECTION 3: PAGE DIRECTORY ANALYSIS ========== */
    cprintf("\nPage Directory Analysis:\n");
    cprintf("========================\n");
    cprintf("Page directory at: 0x%08x\n", (uintptr_t)pgdir);

    /*
     * Analyze the page directory to count mapped pages and show active entries.
     * The page directory contains 1024 entries (NPDENTRIES), each covering 4MB.
     */
    int mapped_pages = 0; /* Total count of mapped 4KB pages */
    int present_pdes = 0; /* Count of present page directory entries */

    /* Iterate through all page directory entries */
    for (int pde_idx = 0; pde_idx < NPDENTRIES; pde_idx++)
    {
        pde_t pde = pgdir[pde_idx]; /* Get page directory entry */

        /* Check if this page directory entry is present (PTE_P bit set) */
        if (pde & PTE_P)
        {
            present_pdes++;
            /* Calculate the starting virtual address for this 4MB region */
            uintptr_t va_start = pde_idx << PDXSHIFT; /* PDXSHIFT = 22 bits */

            /*
             * Only display interesting page directory entries:
             * - Kernel space (>= KERNBASE)
             * - User space below UTOP
             * This filters out empty regions in the middle of the address space
             */
            if (va_start >= KERNBASE || va_start < UTOP)
            {
                cprintf("PDE[%03x]: 0x%08x -> 0x%08x  ",
                        pde_idx, va_start, PTE_ADDR(pde));

                /* Display page directory entry permission flags */
                if (pde & PTE_P)
                    cprintf("P"); /* Present */
                if (pde & PTE_W)
                    cprintf("W"); /* Writable */
                if (pde & PTE_U)
                    cprintf("U"); /* User accessible */
                cprintf("\n");

                /*
                 * Count mapped pages in this page table.
                 * Each page directory entry points to a page table with 1024 entries,
                 * each representing a 4KB page.
                 */
                pte_t *pt = KADDR(PTE_ADDR(pde)); /* Get page table virtual address */
                for (int pte_idx = 0; pte_idx < NPTENTRIES; pte_idx++)
                {
                    /* If page table entry is present, increment mapped page count */
                    if (pt[pte_idx] & PTE_P)
                    {
                        mapped_pages++;
                    }
                }
            }
        }
    }

    /* ========== SECTION 4: MEMORY STATISTICS ========== */
    cprintf("\nMemory Statistics:\n");
    cprintf("==================\n");
    cprintf("Present page directory entries: %d\n", present_pdes);
    cprintf("Total mapped pages: %d\n", mapped_pages);
    cprintf("Total mapped memory: %dKB\n", mapped_pages * PGSIZE / 1024);
    cprintf("Page size: %dKB\n", PGSIZE / 1024);
    cprintf("Page table size: %dMB\n", PTSIZE / (1024 * 1024));

    return 0;
}

/***** Kernel monitor command interpreter *****/

#define WHITESPACE "\t\r\n "
#define MAXARGS 16

static int
runcmd(char *buf, struct Trapframe *tf)
{
    int argc;
    char *argv[MAXARGS];
    int i;

    // Parse the command buffer into whitespace-separated arguments
    argc = 0;
    argv[argc] = 0;
    while (1)
    {
        // gobble whitespace
        while (*buf && strchr(WHITESPACE, *buf))
            *buf++ = 0;
        if (*buf == 0)
            break;

        // save and scan past next arg
        if (argc == MAXARGS - 1)
        {
            cprintf("Too many arguments (max %d)\n", MAXARGS);
            return 0;
        }
        argv[argc++] = buf;
        while (*buf && !strchr(WHITESPACE, *buf))
            buf++;
    }
    argv[argc] = 0;

    // Lookup and invoke the command
    if (argc == 0)
        return 0;
    for (i = 0; i < ARRAY_SIZE(commands); i++)
    {
        if (strcmp(argv[0], commands[i].name) == 0)
            return commands[i].func(argc, argv, tf);
    }
    cprintf("Unknown command '%s'\n", argv[0]);
    return 0;
}

void monitor(struct Trapframe *tf)
{
    char *buf;

    cprintf("Welcome to the JOS kernel monitor!\n");
    cprintf("Type 'help' for a list of commands.\n");

    while (1)
    {
        buf = readline("K> ");
        if (buf != NULL)
            if (runcmd(buf, tf) < 0)
                break;
    }
}
