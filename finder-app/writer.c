#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>

#define U8 unsigned char

int main (int argc, char** argv)
{
    openlog("writer.c:", LOG_NDELAY, LOG_USER);
    if (argc != 3)
    {
        syslog(LOG_ERR, "Error: Usage - writer.sh writefile writestr");
        return 1;
    }

    char* writefile = argv[1];
    char* writestr = argv[2];

    FILE* fptr = fopen(writefile, "w+");

    if (fptr == NULL)
    {
        syslog(LOG_ERR, "Erroe: %s", strerror(errno));
        return 1;
    }
    
    if ( fprintf(fptr, writestr) == 0)
    {
        syslog(LOG_ERR, "ERROR: ./writer is not ./writer'ing. Failed to write to %s", writefile);
    } else {
        syslog(LOG_DEBUG, "Writing %s to %s", writestr, writefile);
    }
    fclose(fptr);

    return 0;
}