/*
 * Copyright 2010 Rapleaf
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *    http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef CTRMODE_H
#define CTRMODE_H

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include "iaesni.h"
#include "ctrmode_ext.h"

#define BLOCKSIZE 16
#define MAX_OUTPUT_TASKS 1024       //arbitrary

typedef struct crypttask
{
    size_t blocks;
    UCHAR * text;
    UCHAR iv[BLOCKSIZE];
    int taskid;
    int complete;
    struct crypttask * next_task;       //next task for worker thread
    struct crypttask * next_block;      //next block sequentially
} crypttask_t;

typedef struct crypter
{
    pthread_t thread;
    pthread_mutex_t mutex;
    struct crypttask * current_task;
    struct crypttask * last_task;       //optimization
    int num_tasks;
} crypter_t;

int numthreads = 0;
int has_more_input = 1;
crypter_t * crypters;
crypter_t * io_worker;
UCHAR * nonce;
UCHAR * key;
int keysize;
unsigned long next_blockid_lsb;
unsigned long next_blockid_msb;
int next_taskid;

#endif  //CTRMODE_H
