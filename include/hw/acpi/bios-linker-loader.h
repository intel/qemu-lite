#ifndef BIOS_LINKER_LOADER_H
#define BIOS_LINKER_LOADER_H

#include <glib.h>
#include "hw/nvram/fw_cfg.h"

/*
 * Linker/loader is a paravirtualized interface that passes commands to guest.
 * The commands can be used to request guest to
 * - allocate memory chunks and initialize them from QEMU FW CFG files
 * - link allocated chunks by storing pointer to one chunk into another
 * - calculate ACPI checksum of part of the chunk and store into same chunk
 */
#define BIOS_LINKER_LOADER_FILESZ FW_CFG_MAX_FILE_PATH

struct BiosLinkerLoaderEntry {
    uint32_t command;
    union {
        /*
         * COMMAND_ALLOCATE - allocate a table from @alloc.file
         * subject to @alloc.align alignment (must be power of 2)
         * and @alloc.zone (can be HIGH or FSEG) requirements.
         *
         * Must appear exactly once for each file, and before
         * this file is referenced by any other command.
         */
        struct {
            char file[BIOS_LINKER_LOADER_FILESZ];
            uint32_t align;
            uint8_t zone;
        } alloc;

        /*
         * COMMAND_ADD_POINTER - patch the table (originating from
         * @dest_file) at @pointer.offset, by adding a pointer to the table
         * originating from @src_file. 1,2,4 or 8 byte unsigned
         * addition is used depending on @pointer.size.
         */
        struct {
            char dest_file[BIOS_LINKER_LOADER_FILESZ];
            char src_file[BIOS_LINKER_LOADER_FILESZ];
            uint32_t offset;
            uint8_t size;
        } pointer;

        /*
         * COMMAND_ADD_CHECKSUM - calculate checksum of the range specified by
         * @cksum_start and @cksum_length fields,
         * and then add the value at @cksum.offset.
         * Checksum simply sums -X for each byte X in the range
         * using 8-bit math.
         */
        struct {
            char file[BIOS_LINKER_LOADER_FILESZ];
            uint32_t offset;
            uint32_t start;
            uint32_t length;
        } cksum;

        /* padding */
        char pad[124];
    };
} QEMU_PACKED;
typedef struct BiosLinkerLoaderEntry BiosLinkerLoaderEntry;

enum {
    BIOS_LINKER_LOADER_COMMAND_ALLOCATE     = 0x1,
    BIOS_LINKER_LOADER_COMMAND_ADD_POINTER  = 0x2,
    BIOS_LINKER_LOADER_COMMAND_ADD_CHECKSUM = 0x3,
};

enum {
    BIOS_LINKER_LOADER_ALLOC_ZONE_HIGH = 0x1,
    BIOS_LINKER_LOADER_ALLOC_ZONE_FSEG = 0x2,
};

GArray *bios_linker_loader_init(void);

void bios_linker_loader_alloc(GArray *linker,
                              const char *file,
                              uint32_t alloc_align,
                              bool alloc_fseg);

void bios_linker_loader_add_checksum(GArray *linker, const char *file,
                                     GArray *table,
                                     void *start, unsigned size,
                                     uint8_t *checksum);

void bios_linker_loader_add_pointer(GArray *linker,
                                    const char *dest_file,
                                    const char *src_file,
                                    GArray *table, void *pointer,
                                    uint8_t pointer_size);

void *bios_linker_loader_cleanup(GArray *linker);
#endif
