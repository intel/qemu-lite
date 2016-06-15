#include "qemu/osdep.h"
#include <glib.h>
#include "qemu-common.h"
#include "qemu/mmap-alloc.h"
#include "hw/i386/pc.h"
#include "hw/i386/pc_lite_acpi.h"
#include "hw/acpi/acpi.h"
#include "hw/acpi/aml-build.h"
#include "hw/acpi/bios-linker-loader.h"
#include "exec/memory.h"

/* #define DEBUG_PC_LITE_ACPI */
#ifdef DEBUG_PC_LITE_ACPI
#define PC_LITE_ACPI_DPRINTF(fmt, ...) \
    do { printf("PC_LITE_ACPI: " fmt, ## __VA_ARGS__); } while (0)
#else
#define PC_LITE_ACPI_DPRINTF(fmt, ...)
#endif

struct AcpiData {
    MemoryRegion *mr;    /* memory region where ACPI data is */
    void         *src;
    uint64_t     offset; /* offset within the memory region */
    uint64_t     size;   /* size of ACPI data */
};
static struct AcpiData pc_lite_acpi_rsdp_data;   /* RSDP */
static struct AcpiData pc_lite_acpi_table_data; /* Other ACPI tables */
static struct AcpiData pc_lite_acpi_loader_linker;

struct AcpiDataAllocator {
    MemoryRegion *mr;
    uint64_t     start;
    uint64_t     offset;
};
static struct AcpiDataAllocator pc_lite_acpi_himem_allocator;
static struct AcpiDataAllocator pc_lite_acpi_fseg_allocator;

#define PC_LITE_ACPI_HIMEM_SIZE (256 * 1024)
#define PC_LITE_ACPI_FSEG_SIZE  (0x100000 - 0xe0000)

static struct AcpiDataAllocator *pc_lite_acpi_get_allocator(uint8_t zone)
{
    struct AcpiDataAllocator *alloc = NULL;
    if (zone == BIOS_LINKER_LOADER_ALLOC_ZONE_HIGH) {
        alloc = &pc_lite_acpi_himem_allocator;
    } else if (zone == BIOS_LINKER_LOADER_ALLOC_ZONE_FSEG) {
        alloc = &pc_lite_acpi_fseg_allocator;
    }
    return alloc;
}

static struct AcpiData *pc_lite_acpi_get_data(const char *name)
{
    struct AcpiData *data = NULL;
    if (!strncmp(name, ACPI_BUILD_TABLE_FILE, BIOS_LINKER_LOADER_FILESZ)) {
        data = &pc_lite_acpi_table_data;
    } else if (!strncmp(name, ACPI_BUILD_RSDP_FILE, BIOS_LINKER_LOADER_FILESZ)) {
        data = &pc_lite_acpi_rsdp_data;
    }
    return data;
}

static uint64_t pc_lite_acpi_get_addr(struct AcpiData *data)
{
    return data->mr->addr + data->offset;
}

static void *pc_lite_acpi_get_ptr(struct AcpiData *data)
{
    void *ptr = memory_region_get_ram_ptr(data->mr);
    return ptr + data->offset;
}

static int pc_lite_acpi_alloctor_init(struct AcpiDataAllocator *allocator,
                                      const char *name,
                                      uint64_t start, uint64_t size)
{
    void *buf;
    MemoryRegion *mr;

    buf = qemu_ram_mmap(-1, size, 0x1000, true);
    if (buf == MAP_FAILED) {
        return -1;
    }

    mr = g_malloc(sizeof(*mr));
    if (!mr) {
        qemu_ram_munmap(buf, size);
        return -1;
    }

    memory_region_init_ram_ptr(mr, NULL, name, size, buf);
    memory_region_add_subregion_overlap(get_system_memory(), start, mr, 0);
    e820_add_entry(start, size, E820_RESERVED);

    allocator->mr = mr;
    allocator->start = start;
    allocator->offset = 0;

    return 0;
}

static void pc_lite_acpi_alloc_init(PCMachineState *pcms)
{
    uint64_t start;

    assert(pcms->below_4g_mem_size >= PC_LITE_ACPI_HIMEM_SIZE);
    start = pcms->below_4g_mem_size - PC_LITE_ACPI_HIMEM_SIZE;
    pc_lite_acpi_alloctor_init(&pc_lite_acpi_himem_allocator, "acpi-himem",
                               start, PC_LITE_ACPI_HIMEM_SIZE);
    pc_lite_acpi_alloctor_init(&pc_lite_acpi_fseg_allocator, "acpi-fseg",
                               0xe0000, PC_LITE_ACPI_FSEG_SIZE);
}

/* return the offset in the corresponding zone, or ~0 for failure */
static uint64_t pc_lite_acpi_alloc(struct AcpiDataAllocator *alloc,
                                   uint64_t size, uint32_t align)
{
    uint64_t start = alloc->start;
    uint64_t offset = alloc->offset;
    uint64_t max_size = memory_region_size(alloc->mr);
    uint64_t addr;

    addr = ROUND_UP(start + offset, align);
    offset = addr - start;
    if (size > max_size || max_size - size < offset) {
        return ~(uint64_t) 0;
    }
    alloc->offset = offset + size;

    return offset;
}

static int pc_lite_acpi_patch_allocate(BiosLinkerLoaderEntry *entry)
{
    uint8_t zone = entry->alloc.zone;
    struct AcpiDataAllocator *alloc;
    struct AcpiData *data;
    uint64_t offset;
    void *dest;

    alloc = pc_lite_acpi_get_allocator(zone);
    if (!alloc) {
        PC_LITE_ACPI_DPRINTF("Allocate: unknown zone type %u\n", zone);
        return -1;
    }
    data = pc_lite_acpi_get_data(entry->alloc.file);
    if (!data) {
        PC_LITE_ACPI_DPRINTF("Allocate: Unknown file: %s\n",
                             entry->alloc.file);
        return -1;
    }
    assert(data->src);

    offset = pc_lite_acpi_alloc(alloc, data->size, entry->alloc.align);
    if (offset == ~(uint64_t) 0) {
        return -1;
    }

    dest = memory_region_get_ram_ptr(alloc->mr);
    memcpy(dest + offset, data->src, data->size);
    memory_region_set_dirty(alloc->mr, offset, data->size);

    data->mr = alloc->mr;
    data->offset = offset;
    g_free(data->src);
    data->src = NULL;

    PC_LITE_ACPI_DPRINTF("Allocate: file %s, zone %d, align 0x%"PRIx32"\n",
                         entry->alloc.file, zone, entry->alloc.align);
    PC_LITE_ACPI_DPRINTF("          size 0x%"PRIx32", GPA 0x%"PRIx32"\n",
                         (uint32_t) data->size,
                         (uint32_t) acpi_loader_get_addr(data));

    return 0;
}

static int pc_lite_acpi_patch_add_pointer(BiosLinkerLoaderEntry *entry)
{
    struct AcpiData *dest_data, *src_data;
    void *dest;
    uint64_t pointer = 0;
    uint32_t offset = entry->pointer.offset;
    uint32_t size = entry->pointer.size;

    PC_LITE_ACPI_DPRINTF(
        "Add_pointer: dst file %s, src file %s, offset 0x%"PRIx32", size 0x%x\n",
        entry->pointer.dest_file, entry->pointer.src_file,
        entry->pointer.offset, entry->pointer.size);

    dest_data = pc_lite_acpi_get_data(entry->pointer.dest_file);
    if (!dest_data) {
        PC_LITE_ACPI_DPRINTF("Add_pointer: unknown destination file %s\n",
                             entry->pointer.dest_file);
        return -1;
    }
    src_data = pc_lite_acpi_get_data(entry->pointer.src_file);
    if (!src_data) {
        PC_LITE_ACPI_DPRINTF("Add_pointer: unknown source file %s\n",
                             entry->pointer.src_file);
        return -1;
    }

    PC_LITE_ACPI_DPRINTF(
        "             dst @ GPA 0x%"PRIx64", src @ GPA 0x%"PRIx64"\n",
        dest_data->mr->addr, src_data->mr->addr);

    dest = pc_lite_acpi_get_ptr(dest_data);
    memcpy(&pointer, dest + offset, size);
    PC_LITE_ACPI_DPRINTF(
        "             original value 0x%"PRIx64"\n", pointer);
    pointer += pc_lite_acpi_get_addr(src_data);
    PC_LITE_ACPI_DPRINTF(
        "             modified value 0x%"PRIx64"\n", pointer);
    memcpy(dest + offset, &pointer, size);
    memory_region_set_dirty(dest_data->mr, dest_data->offset + offset, size);

    return 0;
}

static int pc_lite_acpi_patch_add_checksum(BiosLinkerLoaderEntry *entry)
{
    struct AcpiData *data;
    uint32_t offset = entry->cksum.offset;
    uint8_t *dest, *cksum;

    data = pc_lite_acpi_get_data(entry->cksum.file);
    if (!data) {
        PC_LITE_ACPI_DPRINTF(
            "Add_checksum: unknown ACPI table %s\n", entry->cksum.file);
        return -1;
    }
    dest = pc_lite_acpi_get_ptr(data);
    cksum = dest + offset;
    *cksum = acpi_checksum(dest + entry->cksum.start, entry->cksum.length);
    memory_region_set_dirty(data->mr, data->offset + offset, sizeof(*cksum));

    PC_LITE_ACPI_DPRINTF("Add_checksum: file %s, offset 0x%"PRIx32", "
                         "start 0x%"PRIx32", length 0x%"PRIx32"\n",
                         entry->cksum.file, entry->cksum.offset,
                         entry->cksum.start, entry->cksum.length);
    PC_LITE_ACPI_DPRINTF("              checksum 0x%02x\n", *cksum);

    return 0;
}

/**
 * Patch guest ACPI which is usually done by guest BIOS.
 */
static int pc_lite_acpi_patch(void)
{
    void *data = pc_lite_acpi_loader_linker.src;
    uint64_t len = pc_lite_acpi_loader_linker.size;
    uint64_t offset;
    BiosLinkerLoaderEntry *entry;
    int rc = 0;

    for (offset = 0; offset < len; offset += sizeof(*entry)) {
        entry = data + offset;
        switch (entry->command) {
        case BIOS_LINKER_LOADER_COMMAND_ALLOCATE:
            rc = pc_lite_acpi_patch_allocate(entry);
            break;
        case BIOS_LINKER_LOADER_COMMAND_ADD_POINTER:
            rc = pc_lite_acpi_patch_add_pointer(entry);
            break;
        case BIOS_LINKER_LOADER_COMMAND_ADD_CHECKSUM:
            rc = pc_lite_acpi_patch_add_checksum(entry);
            break;
        default:
            continue;
        }
    }

    return rc;
}

int pc_lite_acpi_build(PCMachineState *pcms)
{
    pc_lite_acpi_alloc_init(pcms);
    return pc_lite_acpi_patch();
}

void pc_lite_acpi_add_table(GArray *table_data, GArray *linker)
{
    unsigned data_size = acpi_data_len(table_data);
    unsigned linker_size = acpi_data_len(linker);

    pc_lite_acpi_table_data.size = data_size;
    pc_lite_acpi_table_data.src = g_memdup(table_data->data, data_size);
    pc_lite_acpi_loader_linker.size = linker_size;
    pc_lite_acpi_loader_linker.src = g_memdup(linker->data, linker_size);
}

void pc_lite_acpi_add_rsdp(GArray *rsdp)
{
    unsigned rsdp_size = acpi_data_len(rsdp);
    pc_lite_acpi_rsdp_data.size = rsdp_size;
    pc_lite_acpi_rsdp_data.src = g_memdup(rsdp->data, rsdp_size);
}
