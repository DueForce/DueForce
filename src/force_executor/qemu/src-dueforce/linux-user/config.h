/* PMP Modification - Begin */
#include "config.inc"

extern abi_ulong program_code_start, program_code_end, program_code_offset;

extern char buff_insn[128], buff_cg[128], buff_dep[128],
            buff_mem[128], buff_trace[128], buff_sysdump[128],
            buff_force[128], buff_log[128], buff_rpadding[128], buff_errflag[128];

extern GHashTable *recover;
extern GQueue *stack;

extern GSequence *cgs, *deps;
extern GHashTable *memory;

extern GHashTable *blackhole;
extern GSequence *flip;
extern unsigned long flip_idx;

extern GHashTable *loops, *loop_counter;
extern FILE *sysdump;
extern pthread_mutex_t mutex;






extern target_ulong fill_value(void);
extern void fill_memory(target_ulong start, size_t size);
extern void fill_arguments(size_t);

extern int valid_addr(target_ulong insn_addr);
extern int need_handle(target_ulong insn_addr);

extern void dump_env(CPUX86State *env);

extern void timeout_handler(int);
extern void initialize(void);

struct pair {
  target_ulong first;
  target_ulong second;
};

extern int pair_compare(const void *pointera, const void *pointerb, void *data);
/* PMP Modification - End */
