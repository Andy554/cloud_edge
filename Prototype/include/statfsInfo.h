#ifndef STATFSINFO_H
#define STATFSINFO_H
#include <stdio.h>
#include <stdlib.h>
#include <sys/statfs.h>
#include <sys/vfs.h>
#include <string.h>
#include <errno.h>
typedef  struct statfs DISK, *pDISK;
class StatfsInfo
{    
    public:
        StatfsInfo();        
        virtual ~StatfsInfo();        
        int getDiskInfo(const char *path);        
        int calDiskAvailRate();
    private:        
        DISK diskInfo; 
        pDISK pDiskInfo;
};
#endif