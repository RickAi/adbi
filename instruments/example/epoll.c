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
// Modified by B.Kerler to support Android Logcat + NDK9

#define _GNU_SOURCE
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <string.h>
#include <termios.h>
#include <pthread.h>
#include <sys/epoll.h>

#include <jni.h>
#include <stdlib.h>

#include "../base/hook.h"
#include "../base/base.h"

#undef log
#include <android/log.h>

#define LOGI(...) ((void)__android_log_print(ANDROID_LOG_INFO, "hooking", __VA_ARGS__))
#define LOGE(...) ((void)__android_log_print(ANDROID_LOG_ERROR, "hooking", __VA_ARGS__)) 
#define log(...) \
        {FILE *fp = fopen("/data/local/tmp/adbi_example.log", "a+");\
        fprintf(fp, __VA_ARGS__);\
        fclose(fp);}


// this file is going to be compiled into a thumb mode binary

void __attribute__ ((constructor)) my_init(void);

static struct hook_t eph;

// for demo code only
static int counter;

// arm version of hook
extern void* my_dvmHeapSourceAlloc_arm(size_t n);

/*  
 *  log function to pass to the hooking library to implement central loggin
 *
 *  see: set_logfunction() in base.h
 */
static void my_log(char *msg)
{
	LOGI("%s",msg);
}

void* my_dvmHeapSourceAlloc(size_t n)
{
	void* (*orig_dvmHeapSourceAlloc)(size_t n);
	orig_dvmHeapSourceAlloc = (void*)eph.orig;

	hook_precall(&eph);
	void* res = orig_dvmHeapSourceAlloc(n);
	if (counter) {
		hook_postcall(&eph);
		LOGI("dvmHeapSourceAlloc() called\n");
		counter--;
		if (!counter)
			LOGI("removing hook for dvmHeapSourceAlloc()\n");
	}
        
	return res;
}

void my_init(void)
{
	counter = 3;

	LOGI("%s started\n", __FILE__);
 
	set_logfunction(my_log);

	hook(&eph, getpid(), "libdvm.", "_Z18dvmHeapSourceAllocj", my_dvmHeapSourceAlloc_arm, my_dvmHeapSourceAlloc);
}

