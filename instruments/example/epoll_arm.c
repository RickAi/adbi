/*
 *  Collin's Binary Instrumentation Tool/Framework for Android
 *  Collin Mulliner <collin[at]mulliner.org>
 *  http://www.mulliner.org/android/
 *
 *  (c) 2012,2013
 *
 *  License: LGPL v2.1
 *
 */

#include <sys/types.h>
#include <sys/epoll.h>
#include <android/log.h>

extern void* my_dvmHeapSourceAlloc(size_t n);

void* my_dvmHeapSourceAlloc_arm(size_t n)
{
	return my_dvmHeapSourceAlloc(n);
}
