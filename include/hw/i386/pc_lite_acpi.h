#ifndef HW_I386_PC_LITE_ACPI_H
#define HW_I386_PC_LITE_ACPI_H

#include "hw/i386/pc.h"
#include "hw/acpi/bios-linker-loader.h"
#include "qapi/error.h"

void pc_lite_acpi_build(PCMachineState *pcms, BIOSLinker *linker, Error **errp);

#endif
