#!/bin/bash

ANALYSIS=$ROOT/analysis/analysis
DYNINST=$HOME/Dyninst

export LD_LIBRARY_PATH=$DYNINST/exe/lib:$DYNINST/build/tbb/lib:$DYNINST/build/elfutils/lib:$LD_LIBRARY_PATH
export DYNINSTAPI_RT_LIB=$DYNINST/exe/lib/libdyninstAPI_RT.so

$ANALYSIS $@
