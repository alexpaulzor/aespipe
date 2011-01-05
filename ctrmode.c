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

#include "ctrmode.h"

/*
 * do the actual crypt task.
 */
void perform_task(crypttask_t * task)
{
    task -> outputtext = malloc(BLOCKSIZE * task -> blocks);
    switch (keysize)
    {
        case 16:
            intel_AES_encdec128_CTR(task -> inputtext, task -> outputtext, key, task -> blocks, task -> iv);
            break;
        case 24:
            intel_AES_encdec192_CTR(task -> inputtext, task -> outputtext, key, task -> blocks, task -> iv);
            break;
        case 32:
            intel_AES_encdec256_CTR(task -> inputtext, task -> outputtext, key, task -> blocks, task -> iv);
            break;
        default:
            break;
    }

    task -> complete = 1;
}

/*
 * entry point for worker threads.
 */
void * crypt_worker(void * voided_param)
{
    crypter_t * crypter = (crypter_t *)voided_param;

    while (has_more_input || crypter -> current_task != NULL)
    {
        if (crypter -> current_task == NULL) usleep(POLL_INTERVAL);
        else
        {
            perform_task(crypter -> current_task);
            pthread_mutex_lock(&(crypter -> mutex));
            crypter -> current_task = crypter -> current_task -> next_task;
            pthread_mutex_unlock(&(crypter -> mutex));
        }
    }

    fprintf(stderr, "Crypt worker thread finished.\n");

    return NULL;
}

void output_task(crypttask_t * task)
{
    fwrite(task -> outputtext, 1, task -> blocks * BLOCKSIZE, stdout);
}

void * output_worker(void * voided_param)
{
    crypter_t * io_worker = (crypter_t *)voided_param;

    while (has_more_input || io_worker -> current_task != NULL)
    {
        if (io_worker -> current_task == NULL || !(io_worker -> current_task -> complete)) usleep(POLL_INTERVAL);
        else
        {
            output_task(io_worker -> current_task);

            pthread_mutex_lock(&(io_worker -> mutex));
            crypttask_t * oldtask = io_worker -> current_task;
            io_worker -> current_task = io_worker -> current_task -> next_block;
            pthread_mutex_unlock(&(io_worker -> mutex));

            free(oldtask -> inputtext);
            free(oldtask -> outputtext);
            free(oldtask);
        }
    }

    fprintf(stderr, "io_worker finished.\n");

    return NULL;
}
        
void add_task(crypter_t * crypter, crypttask_t * task)
{
   
    pthread_mutex_lock(&(io_worker -> mutex));
    if (io_worker -> current_task == NULL)
    {
        io_worker -> current_task = task;
        io_worker -> last_task = task;
    }
    else
    {
        io_worker -> last_task -> next_block = task;
        io_worker -> last_task = task;
    }
    pthread_mutex_unlock(&(io_worker -> mutex));
    
    pthread_mutex_lock(&(crypter -> mutex));
    if (crypter -> current_task == NULL)
    {
        crypter -> current_task = task;
        crypter -> last_task = task;
    }
    else
    {
        crypter -> last_task -> next_task = task;
        crypter -> last_task = task;
    }
    pthread_mutex_unlock(&(crypter -> mutex));
}

void enqueue_data(UCHAR * input, int size)
{
    crypttask_t * task = malloc(sizeof(crypttask_t));
    task -> inputtext = malloc(size);
    memcpy(task -> inputtext, input, size);
    task -> blocks = (size + BLOCKSIZE - 1) / BLOCKSIZE;   //round up
    //pad remainder with eof = 0x040a
    if (size % BLOCKSIZE != 0)
    {
        for (int i = size % BLOCKSIZE; i < BLOCKSIZE; i += 2)
        {
            task -> inputtext[i] = 0x04;
            task -> inputtext[i + 1] = 0x0a;
        }
    }

    memcpy(task -> iv, next_blockid_msb, sizeof(unsigned long));
    memcpy(&(task -> iv[sizeof(unsigned long)]), next_blockid_lsb, sizeof(unsigned long));
    next_blockid_lsb += task -> blocks;
    if (next_blockid_lsb < task -> blocks) next_blockid_msb++;      // increment more significant bit.
    task -> complete = 0;
    task -> next_task = NULL;
    task -> next_block = NULL;

    add_task(&(crypters[task -> blockid % numthreads]), task);
}

void ctr_finish()
{
    has_more_input = FALSE;
    // wait for queued jobs to finish
    pthread_join(io_worker -> thread, NULL);
}

void ctr_setup(int num_threads, void * key_in, int key_length, char * password_seed)
{
    numthreads = num_threads;

    nonce = malloc(BLOCKSIZE);
    for (int i = 0; i < BLOCKSIZE; i++)
    {
        if (password_seed && strlen(password_seed) > i)
        {
            nonce[i] = password_seed[i];
        }
        else
        {
            nonce[i] = 0;
        }
    }

    keysize = key_length;
    key = malloc(keysize);
    memcpy(key, key_in, keysize);

    next_blockid_lsb = 0;
    next_blockid_msb = 0;

    crypters = malloc(sizeof(crypter_t) * numthreads);;

    for (int i = 0; i < numthreads; i++)
    {
        pthread_mutex_init(&(crypters[i].mutex), NULL);
        crypters[i].current_task = NULL;
        crypters[i].last_task = NULL;
        fprintf(stderr, "Spawning crypt worker thread #%d\n", i);
        pthread_create(&(crypters[i].thread), NULL, crypt_worker, (void *)(&(crypters[i])));
    }

    io_worker = malloc(sizeof(crypter_t));
    pthread_mutex_init(&(io_worker -> mutex), NULL);
    io_worker -> current_task = NULL;
    io_worker -> last_task = NULL;

    fprintf(stderr, "Spawning io_worker thread.\n");
    pthread_create(&(io_worker -> thread), NULL, output_worker, (void *)(io_worker));
    
    has_more_input = 1;
}
