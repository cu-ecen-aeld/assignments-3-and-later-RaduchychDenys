#include "threading.h"
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

// Optional: use these functions to add debug or error prints to your application
#define DEBUG_LOG(msg,...)
//#define DEBUG_LOG(msg,...) printf("threading: " msg "\n" , ##__VA_ARGS__)
#define ERROR_LOG(msg,...) printf("threading ERROR: " msg "\n" , ##__VA_ARGS__)

void* threadfunc(void* thread_param)
{

    // TODO: wait, obtain mutex, wait, release mutex as described by thread_data structure
    // hint: use a cast like the one below to obtain thread arguments from your parameter
    //struct thread_data* thread_func_args = (struct thread_data *) thread_param;

    struct thread_data* data = (struct thread_data*)thread_param;

    usleep(data->wait_to_obtain_ms);

    pthread_mutex_lock(data->mutex);

    usleep(data->wait_to_release_ms);

    //Are I suppossed to do it?
    data->thread_complete_success = true;

    pthread_mutex_unlock(data->mutex);

    return thread_param;
}


bool start_thread_obtaining_mutex(pthread_t *thread, pthread_mutex_t *mutex,int wait_to_obtain_ms, int wait_to_release_ms)
{
    /**
     * TODO: allocate memory for thread_data, setup mutex and wait arguments, pass thread_data to created thread
     * using threadfunc() as entry point.
     *
     * return true if successful.
     *
     * See implementation details in threading.h file comment block
     */

    if(mutex == NULL)
    {
        ERROR_LOG("Can not start thread > invalid arguments -> pointer to the mutex structure is NULL\n");
        return false;
    }

    if ( wait_to_obtain_ms < 0 || wait_to_release_ms < 0 )
    {
        ERROR_LOG("Can not start thread -> ivalid arguments -> wait_to_obtain_ms:%d wait_to_release_ms:%d\n", wait_to_obtain_ms, wait_to_release_ms);
        return false;
    }

    errno = 0;

    int error = 0;
    int status = 0;

    struct thread_data* data = (struct thread_data*)calloc(1, sizeof(struct thread_data));

    if(data == NULL || errno != 0)
    {
        error = errno;
        ERROR_LOG("Allocation memory error:%d %s\n", error, strerror(error));
        return false;
    }

    data->mutex = mutex;

    data->wait_to_obtain_ms = wait_to_obtain_ms;
    data->wait_to_release_ms = wait_to_release_ms;


    status = pthread_create(thread, NULL, &threadfunc, (void*)data);

    if(status)
    {
        error = status;
        ERROR_LOG("Can not create pthread -> errno:%d %s\n", error, strerror(error));
        return false;
    }

    return true;
}

