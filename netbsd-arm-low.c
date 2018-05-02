#include "server.h"
#include "netbsd-low.h"
#include "arch/arm.h"

#include <elf.h>
#include <sys/ptrace.h>
#include <machine/reg.h>

static const gdb_byte arm_nbsd_breakpoint[] = { 0x11, 0x00, 0x00, 0xe6 };
static const int arm_nbsd_bplen = 4;

struct arch_lwp_info
{
};

/* ARM methods to read register sets */
class netbsd_arm_gp_registers : public netbsd_register_set
{
private:
  struct reg *r;
  virtual void init_offset_array ();
  virtual void dump_register_set ();
public:
  netbsd_arm_gp_registers () 
    {
      type = GP_REG;
      get_request = PT_GETREGS;
      set_request = PT_SETREGS;
      r = new struct reg;
      num_registers = 17;
      first_register_number = 0;
      last_register_number = first_register_number + num_registers - 1;
      offset_array = new int[num_registers];
      init_offset_array ();
      regbuf = r;
    }
  ~netbsd_arm_gp_registers () 
    { 
      delete r;
      delete offset_array;
      type = INVALID;
    }
};

class netbsd_arm_fp_registers : public netbsd_register_set
{
private:
  struct fpreg *r;
  virtual void init_offset_array ();
  virtual void dump_register_set () { fprintf (stderr, "Unimplemented.\n"); }
public:
  netbsd_arm_fp_registers () 
    {
      type = FP_REG;
      get_request = PT_GETFPREGS;
      set_request = PT_SETFPREGS;
      r = new struct fpreg;
      num_registers = 37;
      first_register_number = 17;
      last_register_number = first_register_number + num_registers - 1;
      offset_array = new int[num_registers];
      init_offset_array ();
      regbuf = r;
    }
  ~netbsd_arm_fp_registers () 
    { 
      delete r;
      delete offset_array;
      type = INVALID;
    }
};

/* Offsets of registers in struct reg. */
void
netbsd_arm_gp_registers :: init_offset_array ()
{
  offset_array[0] = offsetof (struct reg, r[0]);
  offset_array[1] = offsetof (struct reg, r[1]);
  offset_array[2] = offsetof (struct reg, r[2]);
  offset_array[3] = offsetof (struct reg, r[3]);
  offset_array[4] = offsetof (struct reg, r[4]);
  offset_array[5] = offsetof (struct reg, r[5]);
  offset_array[6] = offsetof (struct reg, r[6]);
  offset_array[7] = offsetof (struct reg, r[7]);
  offset_array[8] = offsetof (struct reg, r[8]);
  offset_array[9] = offsetof (struct reg, r[9]);
  offset_array[10] = offsetof (struct reg, r[10]);
  offset_array[11] = offsetof (struct reg, r[11]);
  offset_array[12] = offsetof (struct reg, r[12]);
  offset_array[13] = offsetof (struct reg, r_sp);
  offset_array[14] = offsetof (struct reg, r_lr);
  offset_array[15] = offsetof (struct reg, r_pc);
  offset_array[16] = offsetof (struct reg, r_cpsr);
}

void
netbsd_arm_gp_registers :: dump_register_set ()
{
  fprintf (stderr, "r0 = 0x%x ", r->r[0]);
  fprintf (stderr, "r1 = 0x%x ", r->r[1]);
  fprintf (stderr, "r2 = 0x%x ", r->r[2]);
  fprintf (stderr, "r3 = 0x%x ", r->r[3]);
  fprintf (stderr, "r4 = 0x%x ", r->r[4]);
  fprintf (stderr, "r5 = 0x%x ", r->r[5]);
  fprintf (stderr, "r6 = 0x%x ", r->r[6]);
  fprintf (stderr, "r7 = 0x%x ", r->r[7]);
  fprintf (stderr, "r8 = 0x%x ", r->r[8]);
  fprintf (stderr, "r9 = 0x%x ", r->r[9]);
  fprintf (stderr, "r10 = 0x%x ", r->r[10]);
  fprintf (stderr, "r11 = 0x%x ", r->r[11]);
  fprintf (stderr, "r12 = 0x%x ", r->r[12]);
  fprintf (stderr, "sp = 0x%x ", r->r_sp);
  fprintf (stderr, "lr = 0x%x ", r->r_lr);
  fprintf (stderr, "pc = 0x%x ", r->r_pc);
  fprintf (stderr, "cpsr = 0x%x ", r->r_cpsr);
  fprintf (stderr, "\n");
}

/* Offsets of registers in struct fpreg. */
void
netbsd_arm_fp_registers :: init_offset_array ()
{
  int base_offset = offsetof (struct fpreg, fpr_vfp);

  offset_array[0] = base_offset + offsetof (struct vfpreg, vfp_fpexc);
  offset_array[1] = base_offset + offsetof (struct vfpreg, vfp_fpscr);
  offset_array[2] = base_offset + offsetof (struct vfpreg, vfp_fpinst);
  offset_array[3] = base_offset + offsetof (struct vfpreg, vfp_fpinst2);
  offset_array[4] = base_offset + offsetof (struct vfpreg, vfp_regs[0]);
  offset_array[5] = base_offset + offsetof (struct vfpreg, vfp_regs[1]);
  offset_array[6] = base_offset + offsetof (struct vfpreg, vfp_regs[2]);
  offset_array[7] = base_offset + offsetof (struct vfpreg, vfp_regs[3]);
  offset_array[8] = base_offset + offsetof (struct vfpreg, vfp_regs[4]);
  offset_array[9] = base_offset + offsetof (struct vfpreg, vfp_regs[5]);
  offset_array[10] = base_offset + offsetof (struct vfpreg, vfp_regs[6]);
  offset_array[11] = base_offset + offsetof (struct vfpreg, vfp_regs[7]);
  offset_array[12] = base_offset + offsetof (struct vfpreg, vfp_regs[8]);
  offset_array[13] = base_offset + offsetof (struct vfpreg, vfp_regs[9]);
  offset_array[14] = base_offset + offsetof (struct vfpreg, vfp_regs[10]);
  offset_array[15] = base_offset + offsetof (struct vfpreg, vfp_regs[11]);
  offset_array[16] = base_offset + offsetof (struct vfpreg, vfp_regs[12]);
  offset_array[17] = base_offset + offsetof (struct vfpreg, vfp_regs[13]);
  offset_array[18] = base_offset + offsetof (struct vfpreg, vfp_regs[14]);
  offset_array[19] = base_offset + offsetof (struct vfpreg, vfp_regs[15]);
  offset_array[20] = base_offset + offsetof (struct vfpreg, vfp_regs[16]);
  offset_array[21] = base_offset + offsetof (struct vfpreg, vfp_regs[17]);
  offset_array[22] = base_offset + offsetof (struct vfpreg, vfp_regs[18]);
  offset_array[23] = base_offset + offsetof (struct vfpreg, vfp_regs[19]);
  offset_array[24] = base_offset + offsetof (struct vfpreg, vfp_regs[20]);
  offset_array[25] = base_offset + offsetof (struct vfpreg, vfp_regs[21]);
  offset_array[26] = base_offset + offsetof (struct vfpreg, vfp_regs[22]);
  offset_array[27] = base_offset + offsetof (struct vfpreg, vfp_regs[23]);
  offset_array[28] = base_offset + offsetof (struct vfpreg, vfp_regs[24]);
  offset_array[29] = base_offset + offsetof (struct vfpreg, vfp_regs[25]);
  offset_array[30] = base_offset + offsetof (struct vfpreg, vfp_regs[26]);
  offset_array[31] = base_offset + offsetof (struct vfpreg, vfp_regs[27]);
  offset_array[32] = base_offset + offsetof (struct vfpreg, vfp_regs[28]);
  offset_array[33] = base_offset + offsetof (struct vfpreg, vfp_regs[29]);
  offset_array[34] = base_offset + offsetof (struct vfpreg, vfp_regs[30]);
  offset_array[35] = base_offset + offsetof (struct vfpreg, vfp_regs[31]);
  offset_array[36] = base_offset + offsetof (struct vfpreg, vfp_regs[32]);
}

netbsd_register_set *netbsd_arm_register_sets[] = { new netbsd_arm_gp_registers (),
                                                    new netbsd_arm_fp_registers (),
                                                    new netbsd_invalid_register_set ()
                                                  };

netbsd_register_set **
netbsd_arm_register_set_info (void)
{
  return netbsd_arm_register_sets;
}

static void
netbsd_arm_arch_setup (struct process_info *proc)
{
  init_registers_netbsd_arm_with_vfpv3 ();

  /* In the absence of AT_HWCAP or similar in the ELF auxiliary vector, assume
  the bare minimum hardware capability. */
  /* Future: Find the hardware capabilities and use the correct tdesc. */
  proc->tdesc = tdesc_netbsd_arm_with_vfpv3;
}

/* No hardware breakpoints on NetBSD. */
static int
netbsd_arm_supports_z_point_type (char z_type)
{
  switch (z_type)
    {
    case Z_PACKET_SW_BP:
      return 1;
    default:
      return 0;
    }
}

static const gdb_byte *
netbsd_arm_sw_breakpoint_from_kind (int kind, int *size)
{
  *size = arm_nbsd_bplen;
  return arm_nbsd_breakpoint;
}

struct netbsd_target_ops the_low_target = {
  NULL,                                 /* new_process */
  NULL,                                 /* delete_process */
  NULL,                                 /* new_lwp */
  NULL,                                 /* delete_lwp */
  netbsd_arm_arch_setup,                /* arch_setup */
  NULL,                                 /* prepare_to_resume */
  netbsd_arm_register_set_info,         /* register_set_info */
  netbsd_arm_supports_z_point_type,     /* supports_z_point_type */
  netbsd_arm_sw_breakpoint_from_kind,   /* sw_breakpoint_from_kind */
};
