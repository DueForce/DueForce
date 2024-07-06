#!/usr/bin/env python
import os
import subprocess
from ducg_path import find_intra_paths, get_path_from_prev

class GroundTruth :
  dep_ground    = None
  addr2tp       = None
  insn_all      = None
  block_all     = None
  func_all      = None
  insn_map      = None
  block_map     = None
  func_map      = None
  cg_all        = None
  icfg          = None
  edge_all      = None
  cfg_edges     = None
  i2f           = None
  f2n           = None
  i2b           = None
  jmptab        = None
  calltab       = None
  caller2callee = None
  ret_blks      = None
  pred_blks     = None
  main          = None
  loops         = None

  PS        = None
  PDF       = None
  DOT       = None
  DATA      = None
  STAT      = None
  TYPE      = None
  CGALL     = None
  JMPTAB    = None
  CFGALL    = None
  INSNALL   = None
  CALLTAB   = None
  DEPGROUND = None

  def __init__(self) :
    pass
  
  @classmethod
  def do_cls_init(cls, work_dir) :
    cls.DATA      = "%s/data" % work_dir
    cls.STAT      = "%s/stats" % cls.DATA
    cls.TYPE      = "%s/type" % cls.DATA
    cls.CGALL     = "%s/cg.all" % cls.DATA
    cls.JMPTAB    = "%s/jmptab" % cls.DATA
    cls.CFGALL    = "%s/cfg.all" % cls.DATA
    cls.CALLTAB   = "%s/calltab" % cls.DATA
    cls.INSNALL   = "%s/insn.all" % cls.DATA
    GROUNDDIR     = os.environ.get("GROUNDDIR")
    cls.DEPGROUND = "%s/data/dep.cov" % GROUNDDIR

    cls.PS        = "%s/graph.ps" % cls.DATA
    cls.PDF       = "%s/graph.pdf" % cls.DATA
    cls.DOT       = "%s/graph.dot" % cls.DATA
  
  @classmethod
  def read_dep_ground(cls, DEPGROUND = None) :
    cls.dep_ground = set()

    if DEPGROUND is not None :
      # read dep from BDA
      with open(DEPGROUND, "r") as f:
        for line in f:
          if line[0] == '#':
            continue
          arr = line.strip().split(" ")
          use = format(int(arr[0], 16), 'x')
          define = format(int(arr[2], 16), 'x')
          # if define not in cls.insn_all or use not in cls.insn_all :
          #   continue
          cls.dep_ground.add((use, define))
    if not os.path.exists(cls.DEPGROUND) :
      return
    with open(cls.DEPGROUND, "r") as f:
      for line in f:
        if line[0] == '#':
          continue
        (use, define) = line.strip().split("->")
        cls.dep_ground.add((use, define))

  @classmethod
  def read_type(cls):
    cls.addr2tp = {}
    with open(cls.TYPE, "r") as f:
      for line in f:
        data = line.strip().split()
        addr = data[0]
        tp = data[1]
        cls.addr2tp[addr] = tp

  @classmethod
  def compare_dep(cls, alpha_deps) :
    beta_deps = cls.dep_ground
    intersection = alpha_deps.intersection(beta_deps)
    difference = alpha_deps.difference(beta_deps)
    fp = 0
    for (use, define) in difference:
      if (use in cls.addr2tp) and (define in cls.addr2tp) and not(cls.addr2tp[use] == cls.addr2tp[define]):
        fp +=1

    return (len(intersection), len(difference), fp)

  # @classmethod
  # def find_loops(cls, blk0, visited_blk) :
  #   cfg_edges = cls.cfg_edges
  #   if blk0 not in cfg_edges :
  #     return 
  #   for blk1 in cls.cfg_edges[blk0] :
  #     if 
    

  @classmethod
  def do_analysis(cls, analysis_sh) :
    cls.insn_all = set()
    cls.block_all = set()
    cls.func_all = set()
    cls.insn_map = {}
    cls.block_map = {}
    cls.func_map = {}
    cls.cg_all = set() 
    cls.icfg = {}
    cls.cfg_edges = set() 
    cls.edge_all = set()
    cls.i2f = {}
    cls.f2n = {}
    cls.i2b = {}
    cls.jmptab = {}
    cls.calltab = {}
    cls.caller2callee = {}
    cls.ret_blks = set()
    cls.pred_blks = set()

    print (analysis_sh)
    subprocess.Popen(analysis_sh, shell=True).wait()

    with open(cls.INSNALL, "r") as f:
      for line in f:
        arr = line.strip().split("||")
        insn_addr = arr[0]
        if "f" in arr:
          func_addr = insn_addr
          cls.func_all.add(func_addr)
          cls.func_map[func_addr] = set()
          cls.f2n[func_addr] = arr[-1]
        if "b" in arr:
          block_addr = insn_addr
          cls.block_all.add(block_addr)
          cls.block_map[block_addr] = []
          cls.func_map[func_addr].add(block_addr)
        if "ret" in arr[1] :
          cls.ret_blks.add(block_addr)
        if "j" in arr[1] and "jmp" not in arr[1]:
          cls.pred_blks.add(block_addr)
        cls.insn_all.add(insn_addr)
        cls.insn_map[insn_addr] = arr[1]
        cls.block_map[block_addr].append(insn_addr)
        cls.i2f[insn_addr] = func_addr
        cls.i2b[insn_addr] = block_addr

    main = ""
    with open(cls.CGALL, "r") as f:
      for line in f:
        line = line.strip()
        if "main" in line:
          main = line.split(":")[1]
          print ("main:", main)
        else:
          (caller_site, callee_entry) = line.split('->')
          # if caller_site in insn_all and callee_entry in insn_all :
          #   edge_all.add((i2b[caller_site], i2b[callee_entry]))
          if (caller_site in cls.insn_all) and (callee_entry in cls.insn_all) and (callee_entry in cls.func_all):
            cls.cg_all.add((cls.i2f[caller_site], callee_entry))
            if cls.i2b[caller_site] not in cls.caller2callee :
              cls.caller2callee[cls.i2b[caller_site]] = set()
            cls.caller2callee[cls.i2b[caller_site]].add(callee_entry)
    cls.main = main

    func_prev = {}
    func_reach = set()
    func_list = set()  
    func_reach.add(main)
    func_list.add(main)
    while len(func_list) > 0:
      func_addr = func_list.pop()
      for (caller_site, callee_entry) in cls.cg_all:
        if (caller_site == func_addr) and (callee_entry not in func_reach):
          func_reach.add(callee_entry)
          func_list.add(callee_entry)
          func_prev[callee_entry] = caller_site
    for insn_addr in cls.insn_all.copy():
      if cls.i2f[insn_addr] not in func_reach:
        cls.insn_all.discard(insn_addr)
    for block_addr in cls.block_all.copy():
      if cls.i2f[block_addr] not in func_reach:
        cls.block_all.discard(block_addr)
    for func_addr in cls.func_all.copy():
      if func_addr not in func_reach:
        cls.func_all.discard(func_addr)
    for (caller_site, callee_entry) in cls.cg_all.copy():
      if caller_site not in func_reach:
        cls.cg_all.discard((caller_site, callee_entry))

    ### DEBUG CODE BEGIN 
    # print(main, "41fb40" in func_reach)
    # curr_func = '41fb40'
    # while curr_func != main :
    #   print(curr_func)
    #   curr_func = func_prev[curr_func]
    # print(curr_func)
    # print(main, "456fe0" in cls.func_all)
    ### DEBUG CODE END 

    with open(cls.CFGALL, "r") as f:
      for line in f:
        line = line.strip()
        (bb_src, bb_trg) = line.split('->')
        if (bb_src in cls.block_all) and (bb_trg in cls.block_all) and (cls.i2f[bb_src] == cls.i2f[bb_trg]):
          cls.cfg_edges.add((bb_src, bb_trg))
        if (bb_src in cls.block_all) and (bb_trg in cls.block_all) and cls.i2f[bb_src] in cls.func_all:
          cls.edge_all.add((bb_src, bb_trg))
          if bb_src not in cls.icfg :
            cls.icfg[bb_src] = set()
          cls.icfg[bb_src].add(bb_trg)

    with open(cls.JMPTAB, "r") as f:
      for line in f:
        (src, dest) = line.strip().split('#')
        if not src in cls.jmptab:
          cls.jmptab[src] = set()
        cls.jmptab[src].add(dest)
        if src in cls.insn_all and dest in cls.insn_all and cls.i2f[src] in cls.func_all:
          cls.edge_all.add((cls.i2b[src], cls.i2b[dest]))
          cls.icfg[cls.i2b[src]].add(cls.i2b[dest])

    print ("jmptab: ")
    print (cls.jmptab)

    with open(cls.CALLTAB, "r") as f:
      for line in f:
        (src, dest) = line.strip().split('$')
        if not src in cls.calltab:
          cls.calltab[src] = set()
        cls.calltab[src].add(dest)
        if src in cls.insn_all and dest in cls.insn_all and cls.i2f[src] in cls.func_all:
          cls.edge_all.add((cls.i2b[src], cls.i2b[dest]))
          cls.icfg[cls.i2b[src]].add(cls.i2b[dest])
          if cls.i2b[src] not in cls.caller2callee :
            cls.caller2callee[cls.i2b[src]] = set()
          cls.caller2callee[cls.i2b[src]].add(cls.i2b[dest])

    print ("calltab: ")
    print (cls.calltab)

  @classmethod
  def do_graph(cls, func_cov, block_cov, cg_cov, insn_cov):
    os.remove(cls.DOT) if os.path.exists(cls.DOT) else None

    insn_uncov = cls.insn_all.difference(insn_cov)
    func_fullcov = cls.func_all.copy()
    for insn_addr in insn_uncov:
      func_fullcov.discard(cls.i2f[insn_addr])

    with open(cls.DOT, "a+") as f:
      f.write('digraph cg {\n');
      f.write('  ratio="fill";\n');
      f.write('  size="11.7,8.3";\n');
      f.write('  orientation="landscape";\n');
      f.write('  margin="0";\n');
      f.write('  label="call graph";\n');
      f.write('  labelloc="b";\n');

      for func_addr in cls.func_all:
        f.write('  func_%s [label="%s\\n%s"];\n' % (func_addr, cls.f2n[func_addr], func_addr))

      for (caller, callee) in cls.cg_all:
        f.write('  func_%s -> func_%s;\n' % (caller, callee))

      for func_addr in func_cov:
        f.write('  func_%s [style="filled", fillcolor="black", fontcolor="white"];\n' % func_addr)

      for func_addr in func_fullcov:
        f.write('  func_%s [shape="record"];\n' % func_addr)

      for (caller, callee) in cg_cov:
        f.write('  func_%s -> func_%s [color="gray:gray"];\n' % (caller, callee))

      f.write("}\n")

  #    for func_addr in func_partcov:
      for func_addr in func_cov:
        f.write('digraph cfg_%s {\n' % cls.f2n[func_addr]);
        f.write('  ratio="fill";\n');
        f.write('  size="8.3,11.7";\n');
        f.write('  margin="0";\n');
        f.write('  label="control flow graph of %s";\n' % cls.f2n[func_addr]);
        for block_addr in cls.func_map[func_addr]:
          label = ""
          for insn_addr in cls.block_map[block_addr]:
            label += "%s %s\\l	" % (insn_addr, cls.insn_map[insn_addr]);
          if block_addr in block_cov:
            f.write('  block_%s [label="%s", shape="record", style="filled", fillcolor="black", fontcolor="white"];\n' % (block_addr, label))
          else:
            f.write('  block_%s [label="%s", shape="record"];\n' % (block_addr, label))
        for (bb_src, bb_trg) in cls.cfg_edges:
          if (bb_src in cls.func_map[func_addr]) and (bb_trg in cls.func_map[func_addr]):
            f.write('  block_%s -> block_%s;\n' % (bb_src, bb_trg))
        f.write("}\n")

    RUNDRAW = "dot -Tps2 %s -o %s" % (cls.DOT, cls.PS)
    RUNCONVERT = "ps2pdf -sPAPERSIZE=a4 -dAutoRotatePages=/All %s %s" % (cls.PS, cls.PDF)
    subprocess.Popen(RUNDRAW, shell=True).wait()
    subprocess.Popen(RUNCONVERT, shell=True).wait()

  @classmethod
  def do_find_loop(cls) :

    def dfs(CFG, curr_blk, color, pre, cycles, entry) :
      # print(curr_blk)
      if curr_blk not in CFG : 
        color[curr_blk] = 2
        return 
      for next_blk in CFG[curr_blk] :
        if next_blk not in color :
          color[next_blk] = 1
          pre[next_blk] = curr_blk
          dfs(CFG, next_blk, color, pre, cycles, entry)
        elif color[next_blk] == 1 and next_blk != entry :
          tmp_blk = curr_blk
          cycle = []
          while tmp_blk != next_blk :
            cycle.append(tmp_blk)
            tmp_blk = pre[tmp_blk]
          cycle.append(next_blk)
          cycles.append(cycle)
      color[curr_blk] = 2

    CFG = {}
    pre = {}
    color = {}
    cycles = []
    for (u, v) in cls.cfg_edges :
      if u == v : continue
      if u not in CFG : CFG[u] = set()
      CFG[u].add(v)
    for func in cls.func_all :
      dfs(CFG = CFG, curr_blk = func, color = color, pre = pre, cycles = cycles, entry = func)
    # dfs(CFG = CFG, curr_blk = '404f20', color = color, pre = pre, cycles = cycles)
    # with open(cls.LOOPALL, "w") as f :
    cls.loops = set()
    for cycle in cycles :
      if len(cycle) < 2 : continue
      loop_insn = None
      call_insn = None
      if cycle[0] in CFG and len(CFG[cycle[0]]) == 2 and (cycle[0] not in cls.ret_blks and cycle[0] not in cls.caller2callee):
        loop_insn = cycle[0]
      elif cycle[-1] in CFG and len(CFG[cycle[-1]]) == 2 and (cycle[-1] not in cls.ret_blks and cycle[-1] not in cls.caller2callee):
        loop_insn = cycle[-1]
      # if cycle[0] in cls.caller2callee :
      #   call_insn = cycle[0]
      # elif cycle[-1] in cls.caller2callee :
      #   call_insn = cycle[-1]
      if loop_insn is None : continue
      # print(loop_insn)
      branches = cls.get_predicate_branch(insn = loop_insn)
      if branches[0] in cycle :
        cls.loops.add((loop_insn, 'T'))
      else :
        cls.loops.add((loop_insn, 'F'))

  # return [target_addr, next_addr] [T, F]
  @classmethod
  def get_predicate_branch(cls, insn) :
    bb0 = cls.i2b[insn]
    if (len(cls.icfg[bb0]) != 2) :
      print("pred without 2 branches ", insn, bb0, cls.icfg[bb0])
    assert (len(cls.icfg[bb0]) == 2)
    branches = []
    for bb1 in cls.icfg[bb0] :
      branches.append(int(bb1, 16))
    if branches[0] > branches[1] : branches.reverse()
    if branches[0] > int(bb0, 16) : branches.reverse()
    # may jump to itself
    branches = [format(x, 'x') for x in branches]
    return branches

  @classmethod
  def is_call_blk(cls, blk) :
    return blk in cls.caller2callee

  @classmethod
  def is_ret_blk(cls, blk) :
    return blk in cls.ret_blks

  @classmethod
  def is_pred_blk(cls, blk) :
    return blk in cls.pred_blks

  @classmethod
  def get_last_insn(cls, blk) :
    # assert(blk in cls.blk_all)
    insn = cls.block_map[blk][-1]
    return insn

  @classmethod
  def find_exit_func(cls, CFG) :
    funcs_with_return = set()
    invalid_bbs = set()
    multiexit_funcs = set()
    for bb in cls.ret_blks :
      funcs_with_return.add(cls.i2f[bb])

    funcs_exit = cls.func_all - funcs_with_return
    for caller, callees in cls.caller2callee.items() :
      for callee in callees :
        if cls.i2f[caller] not in cls.func_all :
          continue
        func0 = cls.i2f[caller]
        func1 = cls.i2f[callee]
        if (func0 not in funcs_exit) and (func1 in funcs_exit) : 
          invalid_bbs.add(caller)
          multiexit_funcs.add(func0)

    BLACKHOLES = []
    for func in multiexit_funcs :
      prev = find_intra_paths(CFG, func, invalid_bbs)
      for ret_blk in cls.ret_blks :
        if cls.i2f[ret_blk] == func :
          path = get_path_from_prev(src = func, dest = ret_blk, prev = prev)
          BLACKHOLES.append(path)

    print(BLACKHOLES)
    print(multiexit_funcs)

    return BLACKHOLES
