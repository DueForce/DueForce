#!/usr/bin/env python
import os
import subprocess
import random
from dueforce_ground import GroundTruth

def trim_callstack(callstack, depth) :
  ''' flow sensitive & context insensitive'''
  if depth == 0 : 
    return ""
  if depth <= len(callstack) :
    return "||".join(callstack[-depth:])
  return "||".join(callstack)

class Execution :
  dep_cov       = set()
  dep_blk_cov   = set()
  insn_cov      = set()
  block_cov     = set()
  edge_cov      = set()
  func_cov      = set()
  cg_cov        = set()
  states        = set()
  blk2def_addr  = {}
  insn2def_addr = {}
  GBlk2MemWrite = {}
  GBlk2MemRead  = {}
  inverted_index= {}

  TRACE         = None
  FORCE         = None
  ERROR         = None
  CGTMP         = None
  MEMTMP        = None
  DEPTMP        = None
  LOOPTMP       = None
  INSNTMP       = None
  ERRFLAG       = None
  DEP_COV       = None

  def __init__(self, round_cnt, scheme, s) :
    self.round_cnt = round_cnt
    self.scheme = scheme
    self.preds = None
    self.trace = None
    self.s = s
  
  @classmethod
  def read_insn_tmp(cls, insn_all, block_all, func_all, edge_all, i2b, DUMP_INSN) :
    insn_tmp = set()
    block_tmp = set()
    func_tmp = set()
    edge_tmp = set()
    trace_tmp = []

    if DUMP_INSN == False :
      return None

    try :
      with open(cls.INSNTMP, "r") as f:
        last_bb = None
        for line in f:
          line = line.strip()
          if line in insn_all:
            insn_tmp.add(line)
            curr_bb = i2b[line]
            if (last_bb, curr_bb) in edge_all :
              edge_tmp.add((last_bb, curr_bb))
            last_bb = curr_bb
          else :
            last_bb = None
          if line in block_all:
            if line not in block_tmp:
              trace_tmp.append(line)
            block_tmp.add(line)
          if line in func_all:
            func_tmp.add(line)
      cls.insn_cov = cls.insn_cov.union(insn_tmp)
      cls.block_cov = cls.block_cov.union(block_tmp)
      cls.func_cov = cls.func_cov.union(func_tmp)
      cls.edge_cov = cls.edge_cov.union(edge_tmp)
    except :
      print("[ERROR] : INSNTMP NOT EXISTS")
      return None

    return trace_tmp

  @classmethod
  def read_dep_tmp(cls, insn_all, i2b, DUMP_DEP, dep_ground) :
    dep_tmp = set()
    isuseful = False

    if DUMP_DEP == False :
      return False

    try :
      with open(cls.DEPTMP, "r") as f:
        for line in f:
          if line[0] == '#':
            continue
          (use, define) = line.strip().split("->")
          if (use in insn_all) and (define in insn_all) :
            dep_tmp.add((use, define))
            # if i2b[use] != i2b[define] :
            cls.dep_blk_cov.add((i2b[use], i2b[define]))
    except :
      # dep.tmp not exists
      return False

    ''' only count memory dependence in dep_ground'''
    # if len((dep_tmp-cls.dep_cov).intersection(dep_ground)) > 0 :
    #   isuseful = True
    ''' count all memory dependence'''
    if not dep_tmp.issubset(cls.dep_cov) :
      isuseful = True
    cls.dep_cov.update(dep_tmp)
    return isuseful

  @classmethod
  def read_trace(cls, insn_all, jmptab, calltab) :
    preds = []
    with open(cls.TRACE, "r") as f:
      for line in f:
        if ":" in line:
          (src, dest) = line.strip().split(':')
          if src not in insn_all :
            continue
          preds += [(src, dest)]
        elif "#" in line:
          (src, dest) = line.strip().split('#')
          if not src in jmptab or not src in insn_all or not dest in insn_all:
            continue
          preds += [(src, dest)]
        elif "$" in line:
          (src, dest) = line.strip().split('$')
          if not src in calltab or not src in insn_all or not dest in insn_all:
            continue
          preds += [(src, dest)]
    return preds

  @classmethod
  def read_mem_tmp(cls, insn_all, i2b, DUMP_MEM, depth) :
    if not os.path.exists(cls.MEMTMP) or DUMP_MEM == False :
      return

    ''' update after each execution to save time '''
    # cls.blk2def_addr.clear()
    cls.states.clear()
    cls.states = set()
    seed = random.random()
    # if seed < 0.5 : 
    #   return 
    with open(cls.MEMTMP, "r") as f:
      stackframe = [0]
      callstack = ["main"]
      for line in f:
        line = line.strip().split(' ')
        opch, insn, memaddr, memsize, memval = line
        if insn not in insn_all : continue

        blk = i2b[insn]
        ebp = stackframe[-1]
        esp = int(memaddr, 16)

        ''' PAMA dependency has no contribution to posterior-analysis '''
        # if esp <= 0x400000 : continue

        ''' memory access on -xxx(ebp) won't has no contribution to caller function '''
        # inner = esp < ebp and (ebp-esp) <= 0x10000

        ''' the posterior analysis is context-sensitive '''
        map_cs = trim_callstack(callstack = callstack, depth = depth)

        blk2mem = cls.GBlk2MemRead if opch == 'r' else cls.blk2def_addr
        key = (map_cs, blk)
        if key not in blk2mem : blk2mem[key] = set()
        for offset in range(0, int(memsize), 4) : 
          memm = format(esp + offset, 'x')
          # key = blk
          blk2mem[key].add(memm)
          # if opch == 'w' :
            # if blk == '403e30' :
            #   print("blk2def_addr", key, callstack)
            #   assert(False)
            # cls.states.add(("||".join(callstack), blk))
          ### INSN DEBUG - BEGIN ###
          # if opch == 'w' :
          #   if insn not in cls.insn2def_addr :
          #     cls.insn2def_addr[insn] = set()
          #   cls.insn2def_addr[insn].add(memm)
            # if insn == '403e81' :
            #   print("memrange ", key, cls.blk2def_addr[key])
          ### INSN DEBUG - END###

        if insn != GroundTruth.get_last_insn(blk) : continue
        if GroundTruth.is_call_blk(blk) :
          stackframe.append(esp)
          callstack.append(blk)
        elif GroundTruth.is_ret_blk(blk) :
          if len(stackframe) > 1 :
            stackframe.pop()
            callstack.pop()

  @classmethod
  def read_cg_tmp(cls, insn_all, func_all, i2f, DUMP_CG):
    cg_tmp = set()

    if not os.path.exists(cls.CGTMP) or DUMP_CG == False:
      return cg_tmp

    with open(cls.CGTMP, "r") as f:
      for line in f:
        line = line.strip()
        (caller_site, callee_entry) = line.split('->')
        if (caller_site in insn_all) and (callee_entry in func_all):
          cg_tmp.add((i2f[caller_site], callee_entry))
    cls.cg_cov = cls.cg_cov.union(cg_tmp)

  @classmethod
  def do_cls_init(cls, work_dir) :
    data_dir = "%s/data" % work_dir
    cls.ERROR = "%s/error" % work_dir
    cls.TRACE = "%s/trace" % data_dir
    cls.FORCE = "%s/force" % data_dir
    cls.CGTMP = "%s/cg.tmp" % data_dir
    cls.MEMTMP = "%s/mem" % data_dir
    cls.DEPTMP = "%s/dep.tmp" % data_dir
    cls.INSNTMP = "%s/insn.tmp" % data_dir
    cls.LOOPTMP = "%s/loop.tmp" % data_dir
    cls.ERRFLAG = "%s/errflag" % data_dir
    cls.DEP_COV = "%s/dep.cov" % data_dir

  @classmethod
  def set_path_scheme(cls, scheme, jmptab, calltab, loop_all, BLACKHOLE = None) :
    os.remove(cls.FORCE) if os.path.exists(cls.FORCE) else None
    os.remove(cls.LOOPTMP) if os.path.exists(cls.LOOPTMP) else None
    with open(cls.FORCE, "w") as f :
      if BLACKHOLE is not None :
        for src in BLACKHOLE:
          f.write("%s*%s\n" % (src, BLACKHOLE[src]))
      for (src, dest) in scheme :
        if dest == "T" or dest == "F":
          line = src + ":" + dest + "\n"
        elif src in jmptab:
          line = src + "#" + dest + "\n"
        elif src in calltab:
          line = src + "$" + dest + "\n"
        f.write(line)

    with open(cls.LOOPTMP, "w") as f_loop :
      for (src, dest) in scheme :
        # continue
        if (src, dest) in loop_all :
          line = src + ":" + dest + "\n"
          f_loop.write(line)
    
    assert(os.path.exists(cls.FORCE) and os.path.exists(cls.LOOPTMP))
    # print("set path scheme done !!")
    # RUNECHO = "cat %s >&2" % cls.FORCE
    # subprocess.Popen(RUNECHO, shell=True).wait()

  @classmethod
  def clear_tmpfile(cls) :
    os.remove(cls.INSNTMP) if os.path.exists(cls.INSNTMP) else None
    os.remove(cls.MEMTMP) if os.path.exists(cls.MEMTMP) else None
    os.remove(cls.CGTMP) if os.path.exists(cls.CGTMP) else None
    os.remove(cls.DEPTMP) if os.path.exists(cls.DEPTMP) else None
    os.remove(cls.TRACE) if os.path.exists(cls.TRACE) else None
    os.remove(cls.ERRFLAG) if os.path.exists(cls.ERRFLAG) else None

  def do_execution(self) :
    print ("round {} BEGIN with scheme = {}".format(self.round_cnt, self.scheme))
    
    print ("request")
    self.s.sendall("request")
    response = self.s.recv(16)
    print ("response = %s" % response)

  @classmethod
  def is_crash(cls) :
    COPYERR = "cp %s %s/force_`date +%%y_%%m_%%d_%%I_%%M_%%S_%%N`_`cat %s`" % (cls.FORCE, cls.ERROR, cls.ERRFLAG)
    if os.path.exists(cls.ERRFLAG):
      print ("error")
      subprocess.Popen(COPYERR, shell=True).wait()
      return True
    return False

  @classmethod
  def build_inverted_index(cls, trace, DO_KILL) :
    if DO_KILL == False :
      return 
    for blk in trace :
      if blk not in cls.inverted_index :
        cls.inverted_index[blk] = []
      cls.inverted_index[blk].append(trace)

  @classmethod
  def kill_misdep(cls, dep_diff, DO_KILL) :
    if DO_KILL == False :
      dep_recovery = dep_diff.intersection(Execution.dep_blk_cov)
      return dep_recovery
    dep_kill = set()
    for (use, define) in dep_diff :
      if define not in cls.inverted_index : 
        continue
      for trace in cls.inverted_index[define] :
        if use in trace :
          dep_kill.add((use, define))
          break
    print("[+] execution: dep_kill = {}".format (dep_kill))
    return dep_kill

  @classmethod
  def write_dep_cov(cls):
    with open(cls.DEP_COV, "w+") as f:
      for (use, define) in cls.dep_cov:
        line = "%s->%s\n" % (use, define)
        f.write(line)