#!/bin/sh
# Due to the fact that cargo does not enable features when we use
# `cargo build --all --features std` we have to explicitly iterate over
# all crates (see https://github.com/rust-lang/cargo/issues/4753 )
DIRS=`ls -d */`
TARGET="thumbv7em-none-eabi"
cargo clean

for DIR in $DIRS; do
    if [ $DIR = "target/" -o $DIR = "aead/" -o $DIR = "universal-hash/" ]
    then
        continue
    fi
    cd $DIR
    echo Building $DIR
    cargo build --all-features || {
        echo $DIR failed
        exit 1
    }
    cd ..
done
