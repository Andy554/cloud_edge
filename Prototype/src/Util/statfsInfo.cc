#include "../../include/statfsInfo.h" 
StatfsInfo::StatfsInfo()
{
    pDiskInfo = &diskInfo;    
    memset(pDiskInfo, 0, sizeof(DISK));//ctor
}
StatfsInfo::~StatfsInfo()
{
    //dtor
}
//参数：要获取磁盘信息的位置 //返回值：成功返回1，失败返回0
int StatfsInfo::getDiskInfo(const char *path)
{
    char dpath[100];
    int flag = 0;    
    if(NULL != path)
    {
        strcpy(dpath, path);    
    }    
    if(-1 == (flag = statfs(dpath, pDiskInfo)))//获取包含磁盘空间信息的结构体    
    {
        perror("getDiskInfo statfs fail");        
        return 0;    
    }    
    return 1;
} 
//计算磁盘总空间，非超级用户可用空间，磁盘所有剩余空间，计算结果以字符串的形式存储到三个字符串里面，单位为MB
int StatfsInfo::calDiskAvailRate()
{
    unsigned long long total=0, avail=0, free=0, blockSize=0;      
      
    blockSize = pDiskInfo->f_bsize;//每块包含字节大小    
    total = (pDiskInfo->f_blocks * blockSize)>>20;//磁盘总空间    
    avail = (pDiskInfo->f_bavail * blockSize)>>20;//非超级用户可用空间 
    free = (pDiskInfo->f_bfree * blockSize)>>20;//磁盘所有剩余空间
    int rate = (avail * 100) / total;
    //字符串转换    
    printf("total: %lluMB  avail: %lluMB free: %lluMB \n",total, avail, free);
       
    return rate;
}