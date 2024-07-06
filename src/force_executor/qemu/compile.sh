ROOT=$HOME/DueForce
QEMU=$ROOT/qemu
VERSION=$1
SRC=$QEMU/src-$VERSION
BUILD=$QEMU/build-$VERSION
EXE=$QEMU/exe-$VERSION

cd $QEMU

if [ ! -d $BUILD ]; then
  mkdir $BUILD
  mkdir $EXE
  cd $BUILD
  $SRC/configure --enable-debug --disable-pie --disable-system --enable-linux-user --disable-gtk --disable-sdl --disable-vnc --target-list="x86_64-linux-user,i386-linux-user" --enable-pie --enable-kvm --prefix=$EXE
fi

cd $BUILD
echo $SRC/configure --enable-debug --disable-pie --disable-system --enable-linux-user --disable-gtk --disable-sdl --disable-vnc --target-list="x86_64-linux-user,i386-linux-user" --enable-pie --enable-kvm --prefix=$EXE
make -j64
make install
