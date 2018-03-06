#include "analysis.h"
#include <stdio.h>

void* analysis_init(){
    pthread_mutex_lock(&mutex_processing);

    while (1){

        if(proc_buf->count == 0)
            pthread_cond_wait(&cond_processing, &mutex_processing);

        proc_buf->count--;

        printf("AN: %d\n", proc_buf->count);
    }

    pthread_mutex_unlock(&mutex_processing);
}