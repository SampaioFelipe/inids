#ifndef INIDS_THREADS_MANAGER_H
#define INIDS_THREADS_MANAGER_H

#include <pthread.h>

#include "encoding.h"

#define BUFFER_SIZE 20

typedef struct antigen_buffer {
    struct antigen_encode antigens[BUFFER_SIZE];
    int count;
} antigen_buffer;



#endif //INIDS_THREADS_MANAGER_H
