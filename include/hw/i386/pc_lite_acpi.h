#ifndef HW_I386_PC_LITE_ACPI_H
#define HW_I386_PC_LITE_ACPI_H

#include "hw/i386/pc.h"

int pc_lite_acpi_build(PCMachineState *pcms);

void pc_lite_acpi_add_table(GArray *table_data, GArray *linker);
void pc_lite_acpi_add_rsdp(GArray *rsdp);

#endif
