#!/bin/bash

TARGET=`echo $1 | sed 's#.*/##g'`

ROOT=$HOME/DueForce
LOGDIR=$ROOT/Result
QEMU=$ROOT/qemu
HOOK=$ROOT/hook
CONFIG=$QEMU/src-dueforce/linux-user/config.inc

GROUNDDIR=$HOME/Evaluation/$TARGET/ground

DUMP_INSN=True
DUMP_CG=True
DUMP_DEP=True
DUMP_MEM=True
DUMP_TRACE=True
DUMP_SYSCALL=False
DUMP_LOG=False

DO_FORK=True
DO_STATS=True
DO_GRAPH=True
DO_CALLTAB=False
DO_COMPARE=True

ALLOCATE_SIZE=0x400000
TIMEOUT_LIMIT=2
LOOP_LIMIT=5
SERVER_LIMIT=5

do_init() {

  echo 0 | sudo tee /proc/sys/vm/mmap_min_addr
  ulimit -c 0

  if [ -d "$WORKDIR" ]; then
    sudo rm -rf $WORKDIR
  fi
  mkdir -p $WORKDIR

  export ROOT=$ROOT
  export WORKDIR=$WORKDIR
  export GROUNDDIR=$GROUNDDIR
  export LOGDIR=$LOGDIR

  export DUMP_INSN=$DUMP_INSN
  export DUMP_CG=$DUMP_CG
  export DUMP_DEP=$DUMP_DEP
  export DUMP_MEM=$DUMP_MEM

  export DO_FORK=$DO_FORK
  export DO_STATS=$DO_STATS
  export DO_GRAPH=$DO_GRAPH
  export DO_CALLTAB=$DO_CALLTAB
  export DO_COMPARE=$DO_COMPARE

  # export DO_EXPLOIT=$DO_EXPLOIT
  # export DO_KILL=$DO_KILL
  # export DO_GROUND=$DO_GROUND
}


prepare_qemu() {

  rm $CONFIG
  rm $LOGDIR/*

  echo "/* DueForce Modification - Begin */" >> $CONFIG

  if [ "$DUMP_INSN" = "True" ]; then
    echo "#define DUMP_INSN" >> $CONFIG
  else 
    echo "//#define DUMP_INSN" >> $CONFIG
  fi

  if [ "$DUMP_CG" = "True" ]; then
    echo "#define DUMP_CG" >> $CONFIG
  else 
    echo "//#define DUMP_CG" >> $CONFIG
  fi

  if [ "$DUMP_DEP" = "True" ]; then
    echo "#define DUMP_DEP" >> $CONFIG
  else 
    echo "//#define DUMP_DEP" >> $CONFIG
  fi

  if [ "$DUMP_MEM" = "True" ]; then
    echo "#define DUMP_MEM" >> $CONFIG
  else 
    echo "//#define DUMP_MEM" >> $CONFIG
  fi

  if [ "$DUMP_TRACE" = "True" ]; then
    echo "#define DUMP_TRACE" >> $CONFIG
  else 
    echo "//#define DUMP_TRACE" >> $CONFIG
  fi

  if [ "$DUMP_SYSCALL" = "True" ]; then
    echo "#define DUMP_SYSCALL" >> $CONFIG
  else 
    echo "//#define DUMP_SYSCALL" >> $CONFIG
  fi

  if [ "$DUMP_LOG" = "True" ]; then
    echo "#define DUMP_LOG" >> $CONFIG
  else 
    echo "//#define DUMP_LOG" >> $CONFIG
  fi

  if [ "$DO_FORK" = "True" ]; then
    echo "#define DO_FORK" >> $CONFIG
  else 
    echo "//#define DO_FORK" >> $CONFIG
  fi

  echo "" >> $CONFIG

  echo "#define ALLOCATE_SIZE $ALLOCATE_SIZE" >> $CONFIG
  echo "#define TIMEOUT_LIMIT $TIMEOUT_LIMIT" >> $CONFIG
  echo "#define LOOP_LIMIT $LOOP_LIMIT" >> $CONFIG
  echo "#define SERVER_LIMIT $SERVER_LIMIT" >> $CONFIG

  NEST_LIMIT=2
  echo "#define NEST_LIMIT $NEST_LIMIT" >> $CONFIG
  echo "/* DueForce Modification - End */" >> $CONFIG

  echo "$QEMU/compile.sh dueforce 1>/dev/null"
  $QEMU/compile.sh dueforce
}


do_explore() {

  $ROOT/dueforce-random $@

}


do_init
prepare_qemu $@
do_explore $1
