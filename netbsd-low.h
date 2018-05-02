#ifndef NETBSD_LOW_H
#define NETBSD_LOW_H

#include "gdbthread.h"
#include "target/waitstatus.h"

struct arch_process_info
{
};

struct process_info_private 
{
  CORE_ADDR r_debug;
  bool pending_first_stop;
  struct arch_process_info *arch_private;
};

enum regset_type
{
  GP_REG,
  FP_REG,
  EXTENDED_REG,
  INVALID
};

typedef enum regset_type regtype;

class netbsd_register_set
{
protected:
  regtype type;
  int get_request;
  int set_request;
  uint8_t num_registers;
  uint8_t first_register_number;
  uint8_t last_register_number;
  int *offset_array;
  void *regbuf;
  virtual void init_offset_array () = 0; /* Has to be implemented by the arch. */
  virtual void fetch_registers_ptrace ();
  virtual void store_registers_ptrace ();
  virtual void dump_register_set () = 0;
public:
  netbsd_register_set () 
    { 
      type = INVALID; 
      get_request = 0;
      set_request = 0;
      num_registers = 0;
      first_register_number = 0;
      last_register_number = 0;
      offset_array = NULL;
      regbuf = NULL;
    }
  virtual ~netbsd_register_set () = 0;
  regtype get_type () { return type; }
  int getrequest () { return get_request; }
  int setrequest () { return set_request; }
  virtual void fetch_register (struct regcache *, int);
  virtual void store_register (struct regcache *, int);
  virtual bool regset_contains (int regno)
    {
      return ((regno >= first_register_number) && (regno <= last_register_number));
    }
};

class netbsd_invalid_register_set : public netbsd_register_set
{
private:
  virtual void init_offset_array () { }
  virtual void dump_register_set () { }
public:
  netbsd_invalid_register_set () {  }
  ~netbsd_invalid_register_set () { }
  virtual void fetch_register (struct regcache *r, int regno) { }
  virtual void store_register (struct regcache *r, int regno) { }
  virtual bool regset_contains (int regno) { return false; }
};

struct arch_lwp_info;

struct lwp_info 
{
  struct thread_info *thread;
  struct arch_lwp_info *arch_private;
  struct target_waitstatus waitstatus;
  enum target_stop_reason stop_reason;
  struct thread_resume *resume;
};

struct netbsd_target_ops
{
  struct arch_process_info *(*new_process) (void);
  void (*delete_process) (struct arch_process_info *info);
  struct arch_lwp_info *(*new_lwp) (void);
  void (*delete_lwp) (struct arch_lwp_info *);
  void (*arch_setup) (struct process_info *);
  void (*prepare_to_resume) (struct lwp_info *);
  netbsd_register_set **(*register_set_info)(void);
  int (*supports_z_point_type) (char);
  const gdb_byte *(*sw_breakpoint_from_kind) (int, int *);
};

struct netbsd_thread_resume_array
{
  struct thread_resume *resume;
  size_t n;
};

extern struct netbsd_target_ops the_low_target;
extern const struct target_desc *tdesc_netbsd_arm_with_vfpv3;

extern void init_registers_netbsd_arm_with_vfpv3 (void);
#endif /* NETBSD_LOW_H */
