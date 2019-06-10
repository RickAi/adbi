#!/bin/sh

cd hijack/jni
ndk-build
adb push ../libs/armeabi/hijack /data/local/tmp
cd ../..

cd instruments
cd base/jni
ndk-build
cd ../..

cd example/jni
ndk-build
adb push ../libs/armeabi/libexample.so /data/local/tmp
cd ../..

cd ..

