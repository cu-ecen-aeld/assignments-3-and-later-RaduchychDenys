#include "systemcalls.h"
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

/**
 * @param cmd the command to execute with system()
 * @return true if the command in @param cmd was executed
 *   successfully using the system() call, false if an error occurred,
 *   either in invocation of the system() call, or if a non-zero return
 *   value was returned by the command issued in @param cmd.
*/
bool do_system(const char *cmd)
{

/*
 * TODO  add your code here
 *  Call the system() function with the command set in the cmd
 *   and return a boolean true if the system() call completed with success
 *   or false() if it returned a failure
*/
    if(NULL == cmd)
    {
    	fprintf(stderr, "Can not execute command. Command string is NULL\n");
        return false;
    }

    const int result = system(cmd);

    int error = 0;

    if( -1 == result )
    {
        error = errno;
        perror("Can not create child process or its status could not be retrieved");
        fprintf(stderr, "Error:%d %s\n", error, strerror(error));
        return false;
    }

    if( 127 == result )
    {
        error = errno;
        perror("Can not execute shell in the child process");
        fprintf(stderr, "Error:%d %s\n", error, strerror(error));
    }

    if( result != 0)
    {
        perror("Process end with error termination status");
        fprintf(stderr, "Termination status:%d", result);
    }

    return result == 0;
}

/**
* @param count -The numbers of variables passed to the function. The variables are command to execute.
*   followed by arguments to pass to the command
*   Since exec() does not perform path expansion, the command to execute needs
*   to be an absolute path.
* @param ... - A list of 1 or more arguments after the @param count argument.
*   The first is always the full path to the command to execute with execv()
*   The remaining arguments are a list of arguments to pass to the command in execv()
* @return true if the command @param ... with arguments @param arguments were executed successfully
*   using the execv() call, false if an error occurred, either in invocation of the
*   fork, waitpid, or execv() command, or if a non-zero return value was returned
*   by the command issued in @param arguments with the specified arguments.
*/

bool do_exec(int count, ...)
{
    va_list args;
    va_start(args, count);
    char * command[count+1];
    int i;
    for(i=0; i<count; i++)
    {
        command[i] = va_arg(args, char *);
    }
    command[count] = NULL;
    // this line is to avoid a compile warning before your implementation is complete
    // and may be removed
    command[count] = command[count];

/*
 * TODO:
 *   Execute a system command by calling fork, execv(),
 *   and wait instead of system (see LSP page 161).
 *   Use the command[0] as the full path to the command to execute
 *   (first argument to execv), and use the remaining arguments
 *   as second argument to the execv() command.
 *
*/
    va_end(args);

    fflush(stdout);

    int error = 0;
    pid_t wait_result = 0;
    pid_t pid = fork();

    if(-1 == pid)
    {
        error = errno;
        perror("Can not create child process");
        fprintf(stderr, "Error: %d %s\n", error, strerror(error));
        return false;
    }

    if (0 == pid)
    {
        //child process
        int result = 0;
        int child_process_error = 0;

        result = execv(command[0], command);

        if(-1 == result)
        {
            child_process_error = errno;
            perror("Can not execute command in the child process");
            fprintf(stderr, "Result:%d Error: %d %s\n", result, child_process_error, strerror(child_process_error));
            exit(1);
        }
    }
    else
    {
        //parent process
        int wstatus = 0;
        wait_result = waitpid(pid, &wstatus, 0);

        if( -1 == wait_result)
        {
            error = errno;
            perror("Can not wait child process");
            fprintf(stderr, "Error: %d %s\n", error, strerror(error));
            return false;
        }

        if(WIFSIGNALED(wstatus))
        {
            fprintf(stderr, "Child process killed by signal:%d\n", WTERMSIG(wstatus));
            return false;
        }

        if(WIFSTOPPED(wstatus))
        {
            fprintf(stderr, "Child process stopped by signal:%d\n", WSTOPSIG(wstatus));
            return false;
        }

        if(WIFEXITED(wstatus) && 0 == WEXITSTATUS(wstatus))
        {
            return true;
        }
        else
        {
            fprintf(stderr, "do_exec error -> return false. Child process termination error code:%d\n", WEXITSTATUS(wstatus));
            return false;
        }
    }

    return false;
}

/**
* @param outputfile - The full path to the file to write with command output.
*   This file will be closed at completion of the function call.
* All other parameters, see do_exec above
*/
bool do_exec_redirect(const char *outputfile, int count, ...)
{
    va_list args;
    va_start(args, count);
    char * command[count+1];
    int i;
    for(i=0; i<count; i++)
    {
        command[i] = va_arg(args, char *);
    }
    command[count] = NULL;
    // this line is to avoid a compile warning before your implementation is complete
    // and may be removed
    command[count] = command[count];


/*
 * TODO
 *   Call execv, but first using https://stackoverflow.com/a/13784315/1446624 as a refernce,
 *   redirect standard out to a file specified by outputfile.
 *   The rest of the behaviour is same as do_exec()
 *
*/

    va_end(args);

    int error = 0;
    pid_t wait_result = 0;

    if (NULL == outputfile)
    {
		fprintf(stderr, "Can not create file for redirection.Filemane string is NULL\n");
        return false;
    }

    int fd = open(outputfile, O_CREAT | O_WRONLY | O_TRUNC, 0644);

    if (fd < 0)
    {
		error = errno;
        perror("open file failed");
		fprintf(stderr, "Can not open file [%s]. Error:%d %s\n",outputfile, error, strerror(error));
        return false;
    }

    fflush(stdout);

    pid_t pid = fork();

    if(-1 == pid)
    {
        error = errno;
        perror("Can not create child process");
        fprintf(stderr, "Error: %d %s\n", error, strerror(error));
        return false;
    }

    if (0 == pid)
    {
        //child process
        int result = 0;
        int child_process_error = 0;

        if(dup2(fd, 1) < 0 )
        {
	    	error = errno;
            perror("Can not duplicate fd to output fd");
	    	fprintf(stderr, "Can not redirect command output to the file %s. Error:%d %s\n", outputfile, error, strerror(error));
            exit(1);
        }

        close(fd);

        result = execv(command[0], command);

        if(-1 == result)
        {
            child_process_error = errno;
            perror("Can not execute command in the child process");
            fprintf(stderr, "Result:%d Error: %d %s\n", result, child_process_error, strerror(child_process_error));
            exit(1);
        }
    }
    else
    {
        //parent process
        int wstatus = 0;
        wait_result = waitpid(pid, &wstatus, 0);

        close(fd);

        if(-1 == wait_result)
        {
            error = errno;
            perror("Can not wait child process");
            fprintf(stderr, "Error: %d %s\n", error, strerror(error));
            return false;
        }

        if(WIFSIGNALED(wstatus))
        {
            fprintf(stderr, "Child process killed by signal:%d\n", WTERMSIG(wstatus));
            return false;
        }

        if(WIFSTOPPED(wstatus))
        {
            fprintf(stderr, "Child process stopped by signal:%d\n", WSTOPSIG(wstatus));
            return false;
        }

        if(WIFEXITED(wstatus) && 0 == WEXITSTATUS(wstatus))
        {
            return true;
        }
        else
        {
            fprintf(stderr, "do_exec error -> return false. Child process termination error code:%d\n", WEXITSTATUS(wstatus));
            return false;
        }
    }

    return false;
}
