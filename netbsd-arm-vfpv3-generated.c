/* *INDENT-OFF* */ /* THIS FILE IS GENERATED */

/* A register protocol for GDB, the GNU debugger.
   Copyright (C) 2001-2013 Free Software Foundation, Inc.

   This file is part of GDB.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/* This file was created with the aid of ``regdat.sh'' and ``../regformats/arm/netbsd-arm-vfpv3.dat''.  */

#include "server.h"
#include "regdef.h"
#include "tdesc.h"

const struct target_desc *tdesc_netbsd_arm_with_vfpv3;

void
init_registers_netbsd_arm_with_vfpv3 (void)
{
  static struct target_desc tdesc_netbsd_arm_with_vfpv3_s;
  struct target_desc *result = &tdesc_netbsd_arm_with_vfpv3_s;
  tdesc_create_reg ((struct tdesc_feature *) result, "r0",
  0, 0, NULL, 32, NULL);
  tdesc_create_reg ((struct tdesc_feature *) result, "r1",
  0, 0, NULL, 32, NULL);
  tdesc_create_reg ((struct tdesc_feature *) result, "r2",
  0, 0, NULL, 32, NULL);
  tdesc_create_reg ((struct tdesc_feature *) result, "r3",
  0, 0, NULL, 32, NULL);
  tdesc_create_reg ((struct tdesc_feature *) result, "r4",
  0, 0, NULL, 32, NULL);
  tdesc_create_reg ((struct tdesc_feature *) result, "r5",
  0, 0, NULL, 32, NULL);
  tdesc_create_reg ((struct tdesc_feature *) result, "r6",
  0, 0, NULL, 32, NULL);
  tdesc_create_reg ((struct tdesc_feature *) result, "r7",
  0, 0, NULL, 32, NULL);
  tdesc_create_reg ((struct tdesc_feature *) result, "r8",
  0, 0, NULL, 32, NULL);
  tdesc_create_reg ((struct tdesc_feature *) result, "r9",
  0, 0, NULL, 32, NULL);
  tdesc_create_reg ((struct tdesc_feature *) result, "r10",
  0, 0, NULL, 32, NULL);
  tdesc_create_reg ((struct tdesc_feature *) result, "r11",
  0, 0, NULL, 32, NULL);
  tdesc_create_reg ((struct tdesc_feature *) result, "r12",
  0, 0, NULL, 32, NULL);
  tdesc_create_reg ((struct tdesc_feature *) result, "sp",
  0, 0, NULL, 32, NULL);
  tdesc_create_reg ((struct tdesc_feature *) result, "lr",
  0, 0, NULL, 32, NULL);
  tdesc_create_reg ((struct tdesc_feature *) result, "pc",
  0, 0, NULL, 32, NULL);
  tdesc_create_reg ((struct tdesc_feature *) result, "cpsr",
  0, 0, NULL, 32, NULL);
  tdesc_create_reg ((struct tdesc_feature *) result, "fpexc",
  0, 0, NULL, 32, NULL);
  tdesc_create_reg ((struct tdesc_feature *) result, "fpscr",
  0, 0, NULL, 32, NULL);
  tdesc_create_reg ((struct tdesc_feature *) result, "fpinst",
  0, 0, NULL, 32, NULL);
  tdesc_create_reg ((struct tdesc_feature *) result, "fpinst2",
  0, 0, NULL, 32, NULL);
  tdesc_create_reg ((struct tdesc_feature *) result, "d0",
  0, 0, NULL, 64, NULL);
  tdesc_create_reg ((struct tdesc_feature *) result, "d1",
  0, 0, NULL, 64, NULL);
  tdesc_create_reg ((struct tdesc_feature *) result, "d2",
  0, 0, NULL, 64, NULL);
  tdesc_create_reg ((struct tdesc_feature *) result, "d3",
  0, 0, NULL, 64, NULL);
  tdesc_create_reg ((struct tdesc_feature *) result, "d4",
  0, 0, NULL, 64, NULL);
  tdesc_create_reg ((struct tdesc_feature *) result, "d5",
  0, 0, NULL, 64, NULL);
  tdesc_create_reg ((struct tdesc_feature *) result, "d6",
  0, 0, NULL, 64, NULL);
  tdesc_create_reg ((struct tdesc_feature *) result, "d7",
  0, 0, NULL, 64, NULL);
  tdesc_create_reg ((struct tdesc_feature *) result, "d8",
  0, 0, NULL, 64, NULL);
  tdesc_create_reg ((struct tdesc_feature *) result, "d9",
  0, 0, NULL, 64, NULL);
  tdesc_create_reg ((struct tdesc_feature *) result, "d10",
  0, 0, NULL, 64, NULL);
  tdesc_create_reg ((struct tdesc_feature *) result, "d11",
  0, 0, NULL, 64, NULL);
  tdesc_create_reg ((struct tdesc_feature *) result, "d12",
  0, 0, NULL, 64, NULL);
  tdesc_create_reg ((struct tdesc_feature *) result, "d13",
  0, 0, NULL, 64, NULL);
  tdesc_create_reg ((struct tdesc_feature *) result, "d14",
  0, 0, NULL, 64, NULL);
  tdesc_create_reg ((struct tdesc_feature *) result, "d15",
  0, 0, NULL, 64, NULL);
  tdesc_create_reg ((struct tdesc_feature *) result, "d16",
  0, 0, NULL, 64, NULL);
  tdesc_create_reg ((struct tdesc_feature *) result, "d17",
  0, 0, NULL, 64, NULL);
  tdesc_create_reg ((struct tdesc_feature *) result, "d18",
  0, 0, NULL, 64, NULL);
  tdesc_create_reg ((struct tdesc_feature *) result, "d19",
  0, 0, NULL, 64, NULL);
  tdesc_create_reg ((struct tdesc_feature *) result, "d20",
  0, 0, NULL, 64, NULL);
  tdesc_create_reg ((struct tdesc_feature *) result, "d21",
  0, 0, NULL, 64, NULL);
  tdesc_create_reg ((struct tdesc_feature *) result, "d22",
  0, 0, NULL, 64, NULL);
  tdesc_create_reg ((struct tdesc_feature *) result, "d23",
  0, 0, NULL, 64, NULL);
  tdesc_create_reg ((struct tdesc_feature *) result, "d24",
  0, 0, NULL, 64, NULL);
  tdesc_create_reg ((struct tdesc_feature *) result, "d25",
  0, 0, NULL, 64, NULL);
  tdesc_create_reg ((struct tdesc_feature *) result, "d26",
  0, 0, NULL, 64, NULL);
  tdesc_create_reg ((struct tdesc_feature *) result, "d27",
  0, 0, NULL, 64, NULL);
  tdesc_create_reg ((struct tdesc_feature *) result, "d28",
  0, 0, NULL, 64, NULL);
  tdesc_create_reg ((struct tdesc_feature *) result, "d29",
  0, 0, NULL, 64, NULL);
  tdesc_create_reg ((struct tdesc_feature *) result, "d30",
  0, 0, NULL, 64, NULL);
  tdesc_create_reg ((struct tdesc_feature *) result, "d31",
  0, 0, NULL, 64, NULL);
  tdesc_create_reg ((struct tdesc_feature *) result, "d32",
  0, 0, NULL, 64, NULL);

static const char *expedite_regs_netbsd_arm_with_vfpv3[] = { "r11", "sp", "pc", 0 };
static const char *xmltarget_netbsd_arm_with_vfpv3 = "netbsd-arm-with-neon.xml";

#ifndef IN_PROCESS_AGENT
  result->expedite_regs = expedite_regs_netbsd_arm_with_vfpv3;
  result->xmltarget = xmltarget_netbsd_arm_with_vfpv3;
#endif

  init_target_desc (result);

  tdesc_netbsd_arm_with_vfpv3 = result;
}
