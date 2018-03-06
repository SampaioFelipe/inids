#ifndef INIDS_ANALYSIS_H
#define INIDS_ANALYSIS_H

#include <pthread.h>
#include "../globals/encoding.h"
#include "../globals/threads_manager.h"


void* analysis_init();

/* Thread sync */
extern pthread_mutex_t mutex_processing;
extern pthread_cond_t cond_processing;

/* antigens buffers */
extern antigen_buffer *cap_buf;     // capture buffer
extern antigen_buffer *proc_buf;    // process buffer

#endif //INIDS_ANALYSIS_H
