#include "server.h"
#include "environ.h"
#include "hostio.h"
#include "nat/fork-inferior.h"
#include "mem-break.h"
#include "netbsd-low.h"
#include <string.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <elf.h>
#include <link.h>

int using_threads = 1;
static int resume_signal = GDB_SIGNAL_0;
static int memdebug = 0;
static int regdebug = 0;
static int threaddebug = 0;

#define get_thread_lwp(threadp) ((struct lwp_info *)(thread_target_data (threadp)))

/* Add a thread to the thread list and allocate the corresponding lwp structure. 
PTID is the ptid of the thread to be added.*/
static struct lwp_info *
netbsd_add_lwp (ptid_t ptid)
{
  struct lwp_info *lwp;

  lwp = XCNEW (struct lwp_info);
  lwp->arch_private = NULL;
  if (the_low_target.new_lwp)
    {
      lwp->arch_private = the_low_target.new_lwp ();
    }

  /* Allocate an lwp_info structure and back-link to the parent thread structure. */
  lwp->thread = add_thread (ptid, lwp);
  return lwp;
}

/* Delete a thread from the thread list and de-allocate the corresponding lwp 
structure. PTID is the ptid of the thread to be deleted. */
static void
netbsd_remove_lwp (ptid_t ptid)
{
  struct thread_info *thread;
  struct lwp_info *lwp;
  
  thread = find_thread_ptid (ptid);
  lwp = (struct lwp_info *)thread->target_data;
  if (the_low_target.delete_lwp)
    {
      the_low_target.delete_lwp (lwp->arch_private);
    }
  else
    {
      gdb_assert (lwp->arch_private == NULL);
    }
  XDELETE (lwp);
  remove_thread (thread);
}

/* Find the LWP that caused the signal that caused control to be returned to gdbserver.
PID is the pid of the process that has stopped.
Returns the lwp id of the thread that caused the signal. */
static lwpid_t
netbsd_find_event_lwp (pid_t pid)
{
  ptrace_siginfo_t si = {0};

  if ((ptrace (PT_GET_SIGINFO, pid, &si, sizeof si)) != 0)
    {
      perror ("PT_GET_SIGINFO");
      warning ("Unable to find the event lwp id.");
      return 0;
    }
  
  return si.psi_lwpid;
}

/* Wrapper around waitpid(). Call waitpid() in a loop if it is interrupted. */
static pid_t
netbsd_waitpid (const pid_t pid, int *status, const int options)
{
  pid_t ret;
  do {
    ret = waitpid (pid, status, options);
  } while (ret == -1 && errno == EINTR);
  return ret;
}

/* Given the clear demarcation between process id's and LWP id's that exist on OS's
other than GNU/Linux, we have to make certain adjustments when the process stops for the
first time. On Linux, the main thread will invariably have an LWP with lwp id the same
as the pid of the process and hence we can simply make assumptions about the LWP id of
the main thread and can add a thread with ptid (pid, pid, 0). On BSD, we have to find
the LWP id when the process stops next (we cannot call waitpid() at the point where we
set the pending_first_stop flag given how the gdbserver code is structured) and add a
new thread with the correct LWP id after removing the one we had originally inserted.

PROC is the process_info structure corresponding to our inferior process.
*/
static ptid_t
netbsd_first_stop (struct process_info *proc)
{
  pid_t pid = pid_of (proc);
  ptid_t ptid = ptid_build (pid, 0, 0);
  lwpid_t lwpid;
  struct lwp_info *lwp;
  ptrace_event_t pe = {0};

  /* First up, remove the thread we added previously. */
  netbsd_remove_lwp (ptid);

  /* Find the lwp id of the thread that caused us to stop. */
  lwpid = netbsd_find_event_lwp (pid);
  if (lwpid == 0)
    {
      warning ("Continuing without a proper lwp id.");
    }

  /* Construct a ptid and add the thread. */
  ptid = ptid_build (pid, lwpid, 0);
  lwp = netbsd_add_lwp (ptid);

  current_thread = find_thread_ptid (ptid);
  lwp->waitstatus.kind = TARGET_WAITKIND_IGNORE;

  /* If we have to initialise HW breakpoint registers, do that in the following
  functions in the low-level target. */
  if (the_low_target.new_process)
    {
      proc->priv->arch_private = the_low_target.new_process ();
    }
  if (the_low_target.arch_setup)
    {
      the_low_target.arch_setup (proc);
    }

  pe.pe_set_event = PTRACE_LWP_CREATE | PTRACE_LWP_EXIT;
  if ((ptrace (PT_SET_EVENT_MASK, pid, &pe, sizeof pe)) != 0)
    {
      perror ("PT_SET_EVENT_MASK: ");
      warning ("Can debug only single-threaded programs.");
    }
  proc->priv->pending_first_stop = false;
  return ptid;
}

/* Decode the wait status WS and store the correct code in gdbserver's target_waitstatus
structure STATUS. */
static void
store_waitstatus (pid_t pid, target_waitstatus *status, const int ws)
{
  ptrace_siginfo_t info;
  ptrace_state_t state;

  if (WIFEXITED (ws))
    {
      status->kind = TARGET_WAITKIND_EXITED;
      status->value.integer = WEXITSTATUS (ws);
    }
  else if (WIFSTOPPED (ws))
    {
      status->kind = TARGET_WAITKIND_STOPPED;
      status->value.sig = gdb_signal_from_host (WSTOPSIG (ws));
      if (status->value.sig == GDB_SIGNAL_TRAP)
        {
          if ((ptrace (PT_GET_SIGINFO, pid, &info, sizeof info)) != 0)
            {
              perror ("PT_GET_SIGINFO");
              warning ("Unable to find reason for trap.");
              return;
            }
          if (info.psi_siginfo.si_code == TRAP_LWP)
            {
              if ((ptrace (PT_GET_PROCESS_STATE, pid, &state, sizeof state)) != 0)
                {
                  perror ("PT_GET_PROCESS_STATE");
                  warning ("Cannot find thread creation/delete status.");
                  return;
                }

              /* Seems like we have to work around a kernel bug here...*/
              if (state.pe_lwp == 0)
                {
                  status->kind = TARGET_WAITKIND_SPURIOUS;
                  status->value.sig = GDB_SIGNAL_0;
                  fprintf(stderr, "SPURIOUS\n");
                  return;
                }
              switch (state.pe_report_event)
                {
                case PTRACE_LWP_CREATE:
                  status->kind = TARGET_WAITKIND_THREAD_CREATED;
                  break;
                case PTRACE_LWP_EXIT:
                  status->kind = TARGET_WAITKIND_THREAD_EXITED;
                  break;
                default:
                  warning ("Unhandled thread create/exit status returned from ptrace");
                }
              status->value.integer = state.pe_lwp;
            }
        }
      else 
        {
          fprintf (stderr, "Stopped with signal %d\n", 
                  gdb_signal_from_host (WSTOPSIG(ws)));
        }
    }
  else if (WIFSIGNALED (ws))
    {
      status->kind = TARGET_WAITKIND_SIGNALLED;
      status->value.sig = gdb_signal_from_host (WTERMSIG (ws));
      fprintf (stderr, "SIGNALLED: signal %d\n", status->value.sig);
    }
  else
    {
      status->kind = TARGET_WAITKIND_SPURIOUS;
      status->value.integer = 0;
      fprintf (stderr, "SPURIOUS 1:\n");
    }
}

/* The debugger wait loop where we wait for events from the inferior and decide
what to do with said events. PTID is the thread we are waiting for, the event the
inferior generates will be returned in STATUS and OPTIONS are the options are the
options to be passed to waitpid (). */
static ptid_t
netbsd_wait (const ptid_t ptid, target_waitstatus *status, const int options)
{
  pid_t event_pid;
  lwpid_t lwpid;
  ptid_t event_ptid = null_ptid;
  ptid_t child_ptid;
  int wait_status;
  bool report_to_gdb;           /* Report everything to gdb. 
                                TODO: Filter events reported to gdb. */
  struct lwp_info *lwp;
  thread_info *threadp;
  struct process_info *proc = current_process ();

  do
   {
     report_to_gdb = true;
     event_pid = netbsd_waitpid (ptid_get_pid (ptid), &wait_status, options);
     if (event_pid == 0)
       {
         return null_ptid;
       }
     if (event_pid == -1)
       {
         fprintf (stderr, "Child process exited.\n");
         status->kind = TARGET_WAITKIND_SIGNALLED;
         status->value.sig = GDB_SIGNAL_UNKNOWN;
       }
     store_waitstatus (event_pid, status, wait_status);

     if (status->kind == TARGET_WAITKIND_EXITED ||
         status->kind == TARGET_WAITKIND_SIGNALLED)
       {
         event_ptid = ptid_build (event_pid, 0, 0);
       }
     else if (status->kind == TARGET_WAITKIND_THREAD_CREATED ||
              status->kind == TARGET_WAITKIND_THREAD_EXITED)
       {
         struct thread_resume r = { minus_one_ptid, resume_continue, GDB_SIGNAL_0,
                                    0, 0 };
         /* Add/delete thread. */
         lwpid = status->value.integer;
         if (status->kind == TARGET_WAITKIND_THREAD_CREATED)
           {
             child_ptid = ptid_build (event_pid, lwpid, 0);
             lwp = netbsd_add_lwp (child_ptid);
             lwp->waitstatus.kind = TARGET_WAITKIND_IGNORE;
           }
         else
           {
             event_ptid = ptid_build (event_pid, lwpid, 0);
             if (ptid_equal (event_ptid, current_ptid))
               {
                 if (threaddebug)
                   {
                     fprintf (stderr, "Switching current thread. ");
                   }
                 pid_t pid = pid_of (current_process ());
                 struct thread_info *next_current_thread = find_any_thread_of_pid (pid);
                 switch_to_thread (ptid_of (next_current_thread));
                 if (threaddebug)
                   {
                     fprintf (stderr, "New thread is %ld.\n",
                              lwpid_of (next_current_thread));
                   }
               }
             netbsd_remove_lwp (event_ptid);
           }
         report_to_gdb = false;
         the_target->resume (&r, 1);
       }
     else if (status->kind == TARGET_WAITKIND_STOPPED)
       {
         /* We set the pending_first_stop when we created the inferior. If we are seeing
          this inferior for the first time, we have to do a bit of book-keeping for
          which we call netbsd_first_stop (). */
         if (proc->priv->pending_first_stop)
           {
             event_ptid = netbsd_first_stop (proc);
           }
         else
           {
             lwpid = netbsd_find_event_lwp (event_pid);
             event_ptid = ptid_build (event_pid, lwpid, 0);
           }
       }
     else if (status->kind == TARGET_WAITKIND_SPURIOUS)
       {
         /* We have to continue and wait for another event. */
         struct thread_resume r = { minus_one_ptid, resume_continue, GDB_SIGNAL_0,
                                    0, 0 };
         report_to_gdb = false;
         the_target->resume (&r, 1);
       }
     else if (status->kind == TARGET_WAITKIND_IGNORE)
       {
         /* TARGET_WAITKIND_IGNORE means we have to wait again without a resume. */
         report_to_gdb = false;
       }
   } while (report_to_gdb == false); /* TODO: filter out events that need not
                                      necessarily be reported to the client. */
  
 return event_ptid;
}

/* Set the resume request in ARG in the lwp for the thread THREAD. */
static int
netbsd_set_resume_request (thread_info *thread, void *arg)
{
  struct lwp_info *lwp = get_thread_lwp (thread);
  struct netbsd_thread_resume_array *r = (struct netbsd_thread_resume_array *)arg;

  for (int ndx = 0; ndx < r->n; ndx++)
    {
      ptid_t ptid = r->resume[ndx].thread;

      if ((ptid_equal (ptid, minus_one_ptid)) ||  /* All threads have to be resumed. */
          (ptid_equal (ptid, thread->id)) ||      /* This thread has to be resumed. */
         ((ptid_get_pid (ptid) == pid_of (thread)) && /* The pid's match. */
          ((ptid_is_pid (ptid)) || (ptid_get_lwp (ptid) == -1)))) /* And we only have a
                                                                   pid and therefore
                                                                   we resume all
                                                                   threads. */
        {
#if 0
          if ((r->resume[ndx].kind == resume_stop && 
              thread->last_resume_kind == resume_stop) || 
              (r->resume[ndx].kind != resume_stop && 
               thread->last_resume_kind != resume_stop) ||
              (in_queued_stop_replies (entry->id)))
            {
              continue;
            }
#endif
          lwp->resume = &r->resume[ndx];
          thread->last_resume_kind = lwp->resume->kind;

          /* TODO: set step range
             TODO: signals, queueing/dequeueing.
           */
          return 0;
        }
    }
  lwp->resume = NULL;
  return 0;
}

/* Resume one thread specified by THREAD. ARG is an unused parameter mandated by
find_inferior ().*/
static int
netbsd_resume_one_thread (thread_info *thread)
{
  struct lwp_info *lwp = get_thread_lwp (thread);
  int request;
  pid_t pid;
  void *addr;
  int data;

  /* If we don't have a resume request for the thread or if the resume request is of
  type resume_stop, we don't have anything to do. On BSD, it is guaranteed that all
  threads are stopped when any gdbserver code is running, unlike Linux. */
  if (lwp->resume == NULL || lwp->resume->kind == resume_stop)
    {
      return 0;
    }

  if (the_low_target.prepare_to_resume)
    {
      the_low_target.prepare_to_resume (lwp); 
    }

  pid = pid_of (current_process ());

  switch (lwp->resume->kind)
    {
    case resume_step:
      /* This is dead code on ARM since PT_STEP/PT_SETSTEP is not implemented in the
      kernel for ARM. See NetBSD pr/52119 which is open as of this writing. We rely on
      the client doing the sensible thing and not sending 'step' requests over the wire
      for architectures where it is not supported. */
      addr = (void *)1;
      data = lwpid_of (thread);
      request = PT_STEP;
      break;

    case resume_continue:
      /* Due to the synchronous nature of signal delivery on BSD, we should not have a
      situation where two threads are resumed with signals. If we do have that 
      situation, this code should be rewritten along the lines of the Linux code,
      in which we handle thread scheduling ourselves. */
      addr = (void *)0;
      data = lwpid_of (thread);
      if (resume_signal != GDB_SIGNAL_0 && lwp->resume->sig != GDB_SIGNAL_0)
        {
          warning ("Unexpected signal delivery condition: signals "
                   "scheduled for two different threads.");
        }
      else
        {
          resume_signal = lwp->resume->sig;
        }
      request = PT_RESUME;
      break;

    /* We have already handled resume_stop above. */

    default:
      error("Cannot handle resume request of type %d\n", lwp->resume->kind);
    }

  regcache_invalidate_thread (thread);
  if ((ptrace (request, pid, addr, data)) != 0)
    {
       if (errno == ESRCH)
         {
           ptid_t delete_ptid;
           /* This seems to be another kernel bug we have to work around. We
           occasionally are not notified of thread exit messages and thus when we try
           to resume a thread that is in our thread list we are resuming a thread
           that has already exited. If we come here, we need to rebuild the thread
           list. */
           delete_ptid = ptid_build (pid, data, 0);
           netbsd_remove_lwp (delete_ptid);
           return 0;
         }
       perror_with_name ("ptrace: cannot resume thread: ");
    }
  return 0;
}

/* Resume the threads as requested by the client. RESUME_INFO contains the threads to be
resumed and N is the size of the resume_info array. */
static void
netbsd_resume (struct thread_resume *resume_info, size_t n)
{
  struct netbsd_thread_resume_array array = { resume_info, n };

  for_each_thread ([&] (thread_info *thread)
   {
     netbsd_set_resume_request (thread, &array);
   });

  /* TODO: Conditionally resume threads. */
  for_each_thread ([] (thread_info *thread)
    {
      netbsd_resume_one_thread (thread);
    });
  if (ptrace (PT_CONTINUE, pid_of (current_process ()), (void *)1, resume_signal) != 0)
    {
      perror_with_name ("ptrace");
    }
  resume_signal = GDB_SIGNAL_0;
}

/* Callback used create_inferior. */
static void
netbsd_ptrace_fun (void)
{
  if (ptrace (PT_TRACE_ME, 0, NULL, 0) != 0)
    {
      trace_start_error_with_name ("ptrace");
    }
  if (setpgid (0, 0) < 0)
    {
      trace_start_error_with_name ("setpgid");
    }
  if (remote_connection_is_stdio ())
    {
      if (close(0) < 0)
        {
          trace_start_error_with_name ("close");
        }
      if (open ("/dev/null", O_RDONLY) < 0)
        {
          trace_start_error_with_name ("open");
        }
      if (dup2 (2, 1) < 0)
        {
          trace_start_error_with_name ("dup2");
        }
      char msg[] = "stdin/stdout redirected.\n";
      (void) write (2, msg, sizeof msg);
    }
}

/* Add process to the process list. */
static struct process_info *
netbsd_add_process (const pid_t pid, const int attached)
{
  struct process_info *proc = NULL;
  
  proc = add_process (pid, attached);
  proc->priv = XCNEW (struct process_info_private);
  proc->priv->r_debug = 0;
  proc->priv->pending_first_stop = true;
  return proc;
}

/* Create the inferior process. PROGRAM contains the program to be run and PROGRAM_ARGS
has the arguments to the program. */
static int
netbsd_create_inferior (const char *program, const std::vector<char *> &program_args)
{
  ptid_t ptid;
  lwpid_t lwp;
  struct lwp_info *new_lwp = NULL;
  std::string str_program_args = stringify_argv (program_args);
  pid_t pid = fork_inferior (program,
                             str_program_args.c_str (),
                             get_environ ()->envp (),
                             netbsd_ptrace_fun,
                             NULL, NULL, NULL, NULL);
  ptid = ptid_build(pid, 0, 0);
  netbsd_add_process (pid, 0);
  new_lwp = netbsd_add_lwp (ptid);
  new_lwp->waitstatus.kind = TARGET_WAITKIND_IGNORE;
  post_fork_inferior (pid, program);
  return pid;
}

/* Attach to a running process given its pid PID. */
static int
netbsd_attach (unsigned long pid)
{
  ptid_t ptid;
  struct lwp_info *new_lwp = NULL;

  if ((ptrace (PT_ATTACH, pid, (void *)0, 0)) == -1)
    {
      perror_with_name ("PT_ATTACH: ");
    }
  ptid = ptid_build (pid, 0, 0);
  netbsd_add_process (pid, 1);
  new_lwp = netbsd_add_lwp (ptid);
  new_lwp->waitstatus.kind = TARGET_WAITKIND_IGNORE;
  return 0;
}

/* Detach from a process and let it run untraced. PID is the pid of the process to be
detached. */
static int
netbsd_detach (int pid)
{
  struct process_info *proc;
  pid_t inferior_pid;
  int ret = -1;

  proc = find_process_pid (pid);
  if (proc)
    {
      /* TODO: Deliver pending signals if any. */

      if ((ptrace (PT_DETACH, pid, (void *)1, GDB_SIGNAL_0)))
        {
          perror ("PT_DETACH: ");
        }
      the_target->mourn (proc);
      ret = 0;
    }
  return ret;
}

/* Join when a process dies. */
static void
netbsd_join (int pid)
{
}

/* Return 1 if the thread specified by PTID is alive. */
static int
netbsd_thread_alive (ptid_t ptid)
{
  if ((find_thread_ptid (ptid)))
    {
      return 1;
    }
  return 0;
}

/* Callback for when a thread dies. The thread that died is specified by THREAD and
ARG is a void pointer to a process_info structure. Make sure that the thread that
died does in fact belong to the process we are debugging.
Future: multi-process
*/
static int
netbsd_delete_lwp_callback (thread_info *thread, void *arg)
{
  struct process_info *proc = (struct process_info *)arg;
  ptid_t ptid;

  ptid = thread->id;
  if (pid_of (thread) == pid_of (proc))
    {
      netbsd_remove_lwp (ptid);
    }
  return 0;
}

/* Mourn the inferior process in PROC. This means delete all the dynamically allocated
memory for the private and arch_private data and delete the process from the process
list. Additionally, we delete all the process' threads from the thread list. */
static void
netbsd_mourn_inferior (struct process_info *proc)
{
  struct process_info_private *priv;

  for_each_thread ( [&] (thread_info *thread)
    {
      netbsd_delete_lwp_callback (thread, proc);
    });
  priv = proc->priv;
  if (the_low_target.delete_process)
    {
      the_low_target.delete_process (priv->arch_private);
    }
  else
    {
      gdb_assert (priv->arch_private == NULL);
    }
  free (priv);
  proc->priv = NULL;
  remove_process (proc);
}

/* Kill the inferior with pid PID. */
static int
netbsd_kill (int pid)
{
  struct process_info *proc = NULL;
  int status;
  pid_t wpid;

  proc = find_process_pid (pid);
  if (!proc)
    {
      return -1;
    }
  if ((ptrace (PT_KILL, pid, NULL, 0)) != 0)
    {
      perror ("PT_KILL");
      return -1;
    }

  /* Wait for the inferior and mourn it (delete internal data structures associated
  with it. */
  do {
      wpid = waitpid (pid, &status, WNOHANG);
    } while (wpid <= 0);
  the_target->mourn (proc);
  return 0;
}

static void
netbsd_request_interrupt (void)
{
  pid_t pid = pid_of (current_process ());
  kill (-pid, SIGINT);
}

/* Implementation of read/write memory. MEMOP is the memory operation to be performed,
which should be one of PIOD_READ_D, PIOD_WRITE_D or PIOD_READ_AUXV. MEMADDR is the
address in the inferior's virtual address space to be read/written. MYADDR points to
a buffer from/into which read/write is done. LEN is the number of bytes to be
read/written. */
static int
netbsd_readwrite_memory (int memop, CORE_ADDR memaddr, void *myaddr, int len)
{
  struct ptrace_io_desc iovec = {0};
  pid_t pid = pid_of (current_process ());
  int ret;

  gdb_assert (memop == PIOD_READ_D || memop == PIOD_WRITE_D || memop == PIOD_READ_AUXV);

  iovec.piod_op = memop;
  iovec.piod_offs = (void *)memaddr;
  iovec.piod_addr = myaddr;
  iovec.piod_len = len;

  if (memdebug)
    {
      fprintf (stderr, "Memop = %s,", memop == PIOD_READ_D ? "PIOD_READ_D" :
                       (memop == PIOD_WRITE_D ? "PIOD_WRITE_D" : "PIOD_READ_AUXV"));
      fprintf (stderr, "memaddr = 0x%llx ", memaddr);
      if (memop == PIOD_WRITE_D)
        {
          for (int i = 0; i < len; i++)
            {
              fprintf (stderr, "0x%x ", ((char *)myaddr)[i]);
            }
        }
    }

  /* ptrace() does not set errno to EAGAIN to indicate a retry since all errors
   encountered are irrecoverable. Therefore call ptrace just once. */
  ret = ptrace (PT_IO, pid, &iovec, 0);
  if (ret == -1)
    {
      warning ("ptrace: PT_IO failed: %s", strerror (errno));
    }
  if (memdebug)
    {
      if (memop == PIOD_READ_D)
        {
          for (int i = 0; i < len; i++)
            {
              fprintf (stderr, "0x%x ", ((char *)myaddr)[i]);
            }
        }
      fprintf (stderr, "\n");
    }

  return memop == PIOD_READ_AUXV ? iovec.piod_len : ret;
}

/* The actual memory read function. See documentation for netbsd_readwrite_memory(). */
static int
netbsd_read_memory (CORE_ADDR memaddr, unsigned char *myaddr, int len)
{
  return netbsd_readwrite_memory (PIOD_READ_D, memaddr, myaddr, len);
}

/* The actual memory write function. See documentation for netbsd_readwrite_memory(). */
static int
netbsd_write_memory (CORE_ADDR memaddr, const unsigned char *myaddr, int len)
{
  return netbsd_readwrite_memory (PIOD_WRITE_D, memaddr, (void *)myaddr, len);
}

/* Read the auxiliary vector. See documentation for netbsd_readwrite_memory(). */
static int
netbsd_read_auxv (CORE_ADDR offset, gdb_byte *myaddr, unsigned int length)
{
  return netbsd_readwrite_memory (PIOD_READ_AUXV, offset, (void *)myaddr, length);
}

/* Fetch registers from inferior. REGCACHE is the regcache into which the output is
put. REGNO is the number of the register to be fetched. */
static void
netbsd_fetch_registers (struct regcache *regcache, int regno)
{
  netbsd_register_set **reg_info = the_low_target.register_set_info ();
  int i = 0;

  if (regno == -1)
    {
      /* regno == -1: Fetch all registers. */
      for (i = 0; reg_info[i]->get_type () != INVALID; i++)
        {
          reg_info[i]->fetch_register (regcache, regno);
        }
    }
  else
    {
      /* Fetch a single register. */
      for (i = 0; reg_info[i]->get_type () != INVALID; i++)
        {
          if (reg_info[i]->regset_contains (regno))
            {
              break;
            }
        }
      if (reg_info[i]->get_type () != INVALID)
        {
          reg_info[i]->fetch_register (regcache, regno);
        }
      else
        {
          warning ("Not fetching register %d which is not contained in any regset.",
                  regno);
        }
    }
}

/* Write the inferior's registers. REGCACHE is the regcache from which the input is
taken. REGNO is the number of the register to be stored. */
static void
netbsd_store_registers (struct regcache *regcache, int regno)
{
  netbsd_register_set **reg_info = the_low_target.register_set_info ();
  int i = 0;

  if (regno == -1)
    {
      /* Store all registers from regcache. */
      for (i = 0; reg_info[i]->get_type () != INVALID; i++)
        {
          reg_info[i]->store_register (regcache, regno);
        }
    }
  else
    {
      /* Store a single register. */
      for (i = 0; reg_info[i]->get_type () != INVALID; i++)
        {
          /* Find the regset to which this register belongs. */
          if (reg_info[i]->regset_contains (regno))
            {
              break;
            }
        }
      if (reg_info[i]->get_type () != INVALID)
        {
          /* Store the register, by calling the store_register method of the regset.*/
          reg_info[i]->store_register (regcache, regno);
        }
      else
        {
          warning ("Not storing register %d which is not contained in any regset.",
                  regno);
        }
    }
}

/* Destructor mandated by C++. */
netbsd_register_set :: ~netbsd_register_set ()
{
}

/* Call ptrace to fetch the registers. */
void
netbsd_register_set :: fetch_registers_ptrace ()
{
  pid_t pid = pid_of (current_thread);
  lwpid_t lwpid = lwpid_of (current_thread);

  /* get_request will be speicifc to the derived class. */
  if ((ptrace (get_request, pid, regbuf, lwpid)) != 0)
    {
      perror_with_name ("ptrace");
    }
  if (regdebug)
    {
      fprintf (stderr, "Read registers for lwp %d: ", lwpid);
      dump_register_set ();
    }
}

/* Call ptrace to store the registers. */
void
netbsd_register_set :: store_registers_ptrace ()
{
  pid_t pid = pid_of (current_thread);
  lwpid_t lwpid = lwpid_of (current_thread);

  if (regdebug)
    {
      fprintf (stderr, "Writing registers for lwp %d: ", lwpid);
      dump_register_set ();
    }
  /* set_request will be speicific to the derived class. */
  if ((ptrace (set_request, pid, regbuf, lwpid)) != 0)
    {
      perror_with_name ("ptrace");
    }
}

/* Fetch the register with number REGNO and store it into the regcache REGCACHE. */
void
netbsd_register_set :: fetch_register (struct regcache *regcache, int regno)
{
  gdb_byte *regs = (gdb_byte *)regbuf;
  void *addr = NULL;

  /* Call ptrace to fetch the register set. */
  fetch_registers_ptrace ();

  if (regno == -1)
    {
      /* Store all registers to the regcache. */
      for (int i = first_register_number; i <= last_register_number; i++)
        {
          addr = regs + offset_array[i - first_register_number];
          supply_register (regcache, i, addr);
        }
    }
  else
    {
      /* Store only one register to regcache. */
      gdb_assert (regno >= first_register_number && regno <= last_register_number);
      addr = regs + offset_array[regno - first_register_number];
      supply_register (regcache, regno, addr);
    }
}

/* Write the register with number REGNO to the inferior. The value of the register
to be taken from regcache REGCACHE. */
void
netbsd_register_set :: store_register (struct regcache *regcache, int regno)
{
  gdb_byte *regs = (gdb_byte *)regbuf;
  void *addr = NULL;

  /* Fetch all registers. */
  fetch_registers_ptrace ();
  if (regno == -1)
    {
      /* If regno == -1, overwrite all registers with values from the regcache. */
      for (int i = first_register_number; i <= last_register_number; i++)
        {
          addr = regs + offset_array[i - first_register_number];
          collect_register (regcache, i, addr);
        }
    }
  else
    {
      /* Overwrite the register we want to write with a value from the regcache. */
      gdb_assert (regno >= first_register_number && regno <= last_register_number);
      addr = regs + offset_array[regno - first_register_number];
      collect_register (regcache, regno, addr);
    }
  /* Store the regset. */
  store_registers_ptrace ();
}

/* Return 1 if we support breakpoint of type Z_TYPE, else 0. */
static int
netbsd_supports_z_point_type (char z_type)
{
  return (the_low_target.supports_z_point_type != NULL &&
          the_low_target.supports_z_point_type (z_type));
}

/* Insert a breakpoint of type TYPE at ADDR. Breakpoint size is SIZE and associated
raw breakpoint is BP. */
static int
netbsd_insert_point (enum raw_bkpt_type type, CORE_ADDR addr,
                     int size, struct raw_breakpoint *bp)
{
  if (type == raw_bkpt_type_sw)
    {
      return insert_memory_breakpoint (bp);
    }
  return 1;
}

/* Remove a breakpoint of type TYPE at ADDR. Breakpoint size is SIZE and associated
raw breakpoint is BP. */
static int
netbsd_remove_point (enum raw_bkpt_type type, CORE_ADDR addr,
                     int size, struct raw_breakpoint *bp)
{
  if (type == raw_bkpt_type_sw)
    {
      return remove_memory_breakpoint (bp);
    }
  return 1;
}

/* Return the breakpoint instruction. SIZE will be the length in bytes of the software
breakpoint instruction. */
static const gdb_byte *
netbsd_sw_breakpoint_from_kind (int kind, int *size)
{
  gdb_assert (the_low_target.sw_breakpoint_from_kind != NULL);
  return the_low_target.sw_breakpoint_from_kind (kind, size);
}

/* Return the address of _rtld_debug. */
static CORE_ADDR
get_r_debug ()
{
  AuxInfo a_info = {0, AT_NULL};
  Elf_Phdr *phdrs = NULL;
  Elf_Dyn dynamic;
  int ret = 0;
  int i;
  int ph_num = 0;
  int a_offset = 0;
  CORE_ADDR ph_addr = 0;
  CORE_ADDR dynamic_address = 0;
  CORE_ADDR relocation = -1;
  CORE_ADDR r_debug_address = -1;

  /* Read the ELF auxiliary vector and find the program header vector start address
  and the number of program headers. */
  while (ph_addr == 0 || ph_num == 0)
    {
      a_offset += ret;
      ret = the_target->read_auxv (a_offset, (gdb_byte *)&a_info, sizeof a_info);
      if (ret == 0 || a_info.a_type == AT_NULL)
        {
          break;
        }
      switch (a_info.a_type)
        {
          case AT_PHDR:
            /* Load address of program headers. */
            ph_addr = a_info.a_v;
            break;
          case AT_PHNUM:
            /* Number of program headers. */
            ph_num = a_info.a_v;
            break;
        }
    }
  
  if (ph_addr == 0 || ph_num == 0)
    {
      return -1;
    }

  /* Allocate memory for program headers and read them in. */
  phdrs = XNEWVEC (Elf_Phdr, ph_num);
  if (phdrs == NULL)
    {
      return -1;
    }

  ret = the_target->read_memory (ph_addr, (gdb_byte *)phdrs, 
                                 ph_num * sizeof (Elf_Phdr));
  if (ret != 0)
    {
      XDELETE (phdrs);
      return -1;
    }

  for (i = 0; i < ph_num; i++)
    {
      /* Find the relocation we need to apply. The program headers are loaded starting
       at ph_num and the virtual address is given in p_vaddr. The difference between the
       two is the offset we need to apply to all header addresses subsequently. */
      if (phdrs[i].p_type == PT_PHDR)
        {
          relocation = ph_addr - phdrs[i].p_vaddr;
          break;
        }
    }
  if (relocation == -1)
    {
      XDELETE (phdrs);
      return -1;
    }

  for (i = 0; i < ph_num; i++)
    {
      if (phdrs[i].p_type == PT_DYNAMIC)
        {
          /* Find the load address of the dynamic section. */
          dynamic_address = phdrs[i].p_vaddr + relocation;
          break;
        }
    }
  XDELETE (phdrs);

  if (dynamic_address == 0)
    {
      return -1;
    }

  /* Iterate over the elements in the .dynamic section until we find an element with
  tag DT_DEBUG. */
  while (((ret = the_target->read_memory (dynamic_address, (gdb_byte *)&dynamic,
                                      sizeof dynamic)) == 0) && 
          r_debug_address == -1)
    {
      if (dynamic.d_tag == DT_NULL)
        {
          break;
        }

      /* The address of _rtld_debug will be in the element with tag DT_DEBUG. */
      if (dynamic.d_tag == DT_DEBUG)
        {
          r_debug_address = dynamic.d_un.d_val;
          break;
        }
      dynamic_address += sizeof dynamic;
    }

  /* Return the address we found or -1 if we didn't find the address. */
  return r_debug_address;
}

/* Handle the qxfer:libraries-svr4 client request. */
static int
netbsd_qxfer_libraries_svr4 (const char *annex, unsigned char *readbuf,
                             const unsigned char *writebuf, CORE_ADDR offset, int len)
{
  struct link_map map_element;
  int ret = 0;
  CORE_ADDR link_map_head = -1;
  CORE_ADDR dyn_map;
  CORE_ADDR lm_prev = 0, lm_next;
  int allocated = PATH_MAX * 2 + 1;
  int remaining = allocated;
  int i;
  int document_len = 0;
  char *xml_doc = NULL;
  char *p = NULL;
  bool header_done = false;
  struct process_info_private *priv = current_process ()->priv;

  priv->r_debug = get_r_debug ();
  if (priv->r_debug <= 0)
    {
      return -1;
    }

  /* Skip over the first element (r_version) in _rtld_debug and set dyn_map to the
  address _rtld_debug.r_map. r_map will contain an address which is the first element
  of the shlib list. */
  dyn_map = priv->r_debug + offsetof (struct r_debug, r_map);
  if ((ret = the_target->read_memory (dyn_map, (gdb_byte *)&link_map_head,
                                      sizeof link_map_head)) != 0)
    {
      return -1;
    }

  xml_doc = XNEWVAR (char, allocated);
  if (!xml_doc)
    {
      return -1;
    }
  strncpy (xml_doc, "<library-list-svr4 version=\"1.0\"", allocated);
  p = xml_doc + strlen (xml_doc);
  remaining -= strlen (xml_doc);
  while (link_map_head)
    {
      gdb_byte libname[PATH_MAX + 1];
      
      memset (libname, '\0', sizeof libname);

      /* Read the shared library list. The first node will contain the main
      executable. */
      ret = the_target->read_memory (link_map_head, (gdb_byte *)&map_element,
                                     sizeof map_element);
      if (ret)
        {
          ret = -1;
          goto end;
        }

      /* Read the library name into libname. */
      ret = the_target->read_memory ((CORE_ADDR)map_element.l_name, libname,
                                     sizeof libname);
      if (ret)
        {
          ret = -1;
          goto end;
        }

      libname[sizeof libname - 1] = '\0';
      if (map_element.l_prev != (struct link_map *)lm_prev)
        {
          warning ("Corrupted shlib list.");
        }
      if (map_element.l_prev == 0)
        {
          snprintf (p, remaining, " main-lm=\"%p\">", map_element.l_addr);
          remaining -= strlen (p);
          p += strlen (p);
          header_done = true;
        }
      else
        {
          if (libname[0] != '\0')
            {
              size_t len = 6 * strlen ((char *)libname);
              if (remaining < len + 200)
                {
                  uintptr_t xml_doc_len = p - xml_doc;
                  xml_doc = XRESIZEVEC (char, xml_doc, allocated + len + 200);
                  allocated = allocated + len + 200;
                  p = xml_doc + xml_doc_len;
                  remaining = allocated - xml_doc_len;
                }
              std::string name = xml_escape_text ((char *)libname);
              if (!header_done)
                {
                  snprintf (p, remaining, ">");
                  remaining -= strlen (p);
                  p += strlen (p);
                }
              snprintf (p, remaining,
                       "<library name=\"%s\" lm=\"%p\" l_addr=\"%p\" l_ld=\"%p\"/>",
                        name.c_str (), (void *)link_map_head, map_element.l_addr,
                        map_element.l_ld);
              remaining -= strlen (p);
              p += strlen (p);
            }
        }
      lm_prev = link_map_head;
      link_map_head = (CORE_ADDR)map_element.l_next;
    }
  if (!header_done)
    {
      snprintf (p, remaining, "/>");
      remaining -= strlen (p);
      p += strlen (p);
    }
  else
    {
      snprintf (p, remaining, "</library-list-svr4>");
      remaining -= strlen(p);
      p += strlen (p);
    }

  document_len = strlen (xml_doc);
  if (offset < document_len)
    {
      document_len -= offset;
    }
  else
    {
      document_len = 0;
    }

  if (len > document_len)
    {
      len = document_len;
    }
  memcpy (readbuf, xml_doc + offset, len);
  ret = len;
end:
  if (xml_doc != NULL)
    {
      XDELETE (xml_doc);
    }
  return ret;
}

struct target_ops nbsd_target_ops = {
  netbsd_create_inferior,           /* create_inferior */
  NULL,                             /* post_create_inferior */
  netbsd_attach,                    /* attach */
  netbsd_kill,                      /* kill */
  netbsd_detach,                    /* detach */
  netbsd_mourn_inferior,            /* mourn */
  netbsd_join,                      /* join */
  netbsd_thread_alive,              /* thread_alive */
  netbsd_resume,                    /* resume */
  netbsd_wait,                      /* wait */
  netbsd_fetch_registers,           /* fetch_registers */
  netbsd_store_registers,           /* store_registers */
  NULL,                             /* prepare_to_access_memory */
  NULL,                             /* done_accessing_memory */
  netbsd_read_memory,               /* read_memory */
  netbsd_write_memory,              /* write_memory */
  NULL,                             /* look_up_symbols */
  netbsd_request_interrupt,         /* request_interrupt */
  netbsd_read_auxv,                 /* read_auxv */
  netbsd_supports_z_point_type,     /* supports_z_point_type */
  netbsd_insert_point,              /* insert_point */
  netbsd_remove_point,              /* remove_point */
  NULL,                             /* stopped_by_sw_breakpoint */
  NULL,                             /* supports_stopped_by_sw_breakpoint */
  NULL,                             /* stopped_by_hw_breakpoint */
  NULL,                             /* supports_stopped_by_hw_breakpoint */
  NULL,                             /* supports_hardware_single_step */
  NULL,                             /* stopped_by_watchpoint */
  NULL,                             /* stopped_data_address */
  NULL,                             /* read_offsets */
  NULL,                             /* get_tls_address */
  NULL,                             /* qxfer_spu */
  hostio_last_error_from_errno,     /* hostio_last_error */
  NULL,                             /* qxfer_osdata */
  NULL,                             /* qxfer_siginfo */
  NULL,                             /* supports_non_stop */
  NULL,                             /* async */
  NULL,                             /* start_non_stop */
  NULL,                             /* supports_multi_process */
  NULL,                             /* supports_fork_events */
  NULL,                             /* supports_vfork_events */
  NULL,                             /* supports_exec_events */
  NULL,                             /* handle_new_gdb_connection */
  NULL,                             /* handle_monitor_command */
  NULL,                             /* core_of_thread */
  NULL,                             /* read_loadmap */
  NULL,                             /* process_qsupported */
  NULL,                             /* supports_tracepoints */
  NULL,                             /* read_pc */
  NULL,                             /* write_pc */
  NULL,                             /* thread_stopped */
  NULL,                             /* get_tib_address */
  NULL,                             /* pause_all */
  NULL,                             /* unpause_all */
  NULL,                             /* stabilize_threads */
  NULL,                             /* install_fast_tracepoint_jump_pad */
  NULL,                             /* emit_ops */
  NULL,                             /* supports_disable_randomization */
  NULL,                             /* get_min_fast_tracepoint_insn_len */
  netbsd_qxfer_libraries_svr4,      /* qxfer_libraries_svr4 */
  NULL,                             /* supports_agent */
  NULL,                             /* enable_btrace */
  NULL,                             /* disable_btrace */
  NULL,                             /* read_btrace */
  NULL,                             /* read_btrace_conf */
  NULL,                             /* supports_range_stepping */
  NULL,                             /* pid_to_exec_file */
  NULL,                             /* multifs_open */
  NULL,                             /* multifs_unlink */
  NULL,                             /* multifs_readlink */
  NULL,                             /* breakpoint_kind_from_pc */
  netbsd_sw_breakpoint_from_kind,   /* sw_breakpoint_from_kind */
  NULL,                             /* thread_name */
  NULL,                             /* breakpoint_kind_from_current_state */
  NULL,                             /* supports_software_single_step */
  NULL,                             /* supports_catch_syscall */
  NULL,                             /* get_ipa_tdesc_idx */
  NULL                              /* thread_handle */
};

void initialize_low (void)
{
  set_target_ops (&nbsd_target_ops);
}
