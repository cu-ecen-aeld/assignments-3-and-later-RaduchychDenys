#include <stdio.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#define WRONG_ARGUMENTS_ERROR 1
#define FILE_OPENING_ERROR 1
#define WRITING_FILE_ERROR 1

int main(int argc, char ** argv )
{
    openlog("writer", LOG_CONS | LOG_PID, LOG_USER);

    if(argc < 3)
    {
        syslog(LOG_ERR, "You must provide two argumetns. First is a path to file. Second is a data to write. Provided arguments count:%d", argc -1);
        return WRONG_ARGUMENTS_ERROR;
    }

    ssize_t dataLen = strnlen(argv[2], 1024 * 10);

    if(strnlen(argv[1], 1024) == 0 || dataLen == 0)
    {
        syslog(LOG_ERR, "Argumetns have zero len. You must provide not empty arguments");
        return WRONG_ARGUMENTS_ERROR;
    }

    const char* filePath = argv[1];
    const char* data = argv[2];
    int error = 0;

    int file = open(filePath, O_WRONLY | O_TRUNC | O_CREAT, 0644);

    if (file < 0)
    {
        error = errno;
        syslog(LOG_ERR, "Can not open file [%s] for writing. Error: %d %s", filePath, error, strerror(error));
        return FILE_OPENING_ERROR;

    }

    ssize_t wb = write(file, data, dataLen);

    if (wb > 0)
    {
        syslog(LOG_DEBUG, "Writing %s to %s", data, filePath);
    }
    else
    {
        error = errno;
        syslog(LOG_ERR, "Can not write to file %s. Error: %d %s", filePath, error, strerror(error));
        return WRITING_FILE_ERROR;
    }

    return 0;
}
