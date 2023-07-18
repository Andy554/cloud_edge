/**
 * @file chunkStructure.h
 * @author Zuoru YANG (zryang@cse.cuhk.edu.hk)
 * @brief define the necessary data structure in deduplication
 * @version 0.1
 * @date 2019-12-19
 * 
 * @copyright Copyright (c) 2019
 * 
 */

#ifndef BASICDEDUP_CHUNK_h
#define BASICDEDUP_CHUNK_h

#include "constVar.h"
#include <stdint.h>

typedef struct {
    uint32_t chunkSize;
    uint8_t data[MAX_CHUNK_SIZE];
} Chunk_t;

typedef struct {
    uint64_t fileSize;
    uint64_t totalChunkNum;
} FileRecipeHead_t;

typedef struct {
    union {
        Chunk_t chunk;
        FileRecipeHead_t recipeHead;
    };
    int dataType;
} Data_t;

typedef struct {
    uint32_t chunkSize;
    uint8_t chunkHash[CHUNK_HASH_SIZE];
} SegmentMeta_t;

typedef struct {
   uint32_t chunkNum; 
   uint32_t segmentSize;
   uint32_t minHashVal;
   uint8_t minHash[CHUNK_HASH_SIZE];
   uint8_t* buffer;
   SegmentMeta_t* metadata;
} Segment_t;

typedef struct {
    uint8_t containerName[CONTAINER_ID_LENGTH];
    uint32_t offset;
    uint32_t length;
} RecipeEntry_t;

typedef struct {
    uint8_t Hash[CHUNK_HASH_SIZE]; 
} RecipeEntrywithMLE_t;

typedef struct {
    uint64_t sendChunkBatchSize;
    uint64_t sendRecipeBatchSize;
    uint64_t topKParam;
} EnclaveConfig_t;

typedef struct {
    uint64_t uniqueChunkNum;
    uint64_t uniqueDataSize;
    uint64_t logicalChunkNum;
    uint64_t logicalDataSize;
    uint64_t compressedSize;
    double enclaveProcessTime;
    uint64_t indeduptime;
    uint64_t outdeduptime;
    uint64_t sftime;
    uint64_t deltatime;
    uint64_t indeltatime;
    uint64_t outdeltatime;
    uint64_t conI_Otime;
    uint64_t conupdatetime;
    uint64_t delaytime;
    uint64_t delayupdatetime;
    uint64_t delayprocesstime;
    uint64_t processtime;
    uint64_t deltaprocesstime;
    uint64_t uniqueprocesstime;
    uint64_t backup_unique;
    uint64_t backup_delta;
    uint64_t backup_indelta;
    uint64_t backup_outdelta;
    uint64_t backup_delay_push;
    uint64_t backup_delay_pop;
    uint64_t backup_total;
    uint64_t backup_enclave_total;




#if (SGX_BREAKDOWN == 1)
    double dataTranTime;
    double fpTime;
    double freqTime;
    double firstDedupTime;
    double secondDedupTime;
    double compTime;
    double encTime;
#endif
} EnclaveInfo_t;

typedef struct {
    int messageType;
    uint32_t clientID;
    uint32_t dataSize;
    uint32_t currentItemNum;
} NetworkHead_t;

typedef struct {
    NetworkHead_t* header;
    uint8_t* sendBuffer;
    uint8_t* dataBuffer;
} SendMsgBuffer_t;

typedef struct {
    uint32_t recipeNum;
    uint8_t* entryList;
} Recipe_t;

typedef struct {
    uint32_t containerID; // the ID to current restore buffer
    uint8_t chunkHash[CHUNK_HASH_SIZE];
} EnclaveRecipeEntry_t;

typedef struct {
    uint8_t containerName[CONTAINER_ID_LENGTH]; 
    uint32_t offset;
} CacheIndex_t;

typedef struct {
    char containerID[CONTAINER_ID_LENGTH];
    uint8_t body[MAX_CONTAINER_SIZE]; 
    uint32_t currentSize;
} Container_t;

typedef struct {
    uint8_t segmentHash[CHUNK_HASH_SIZE];
    uint8_t binID_[SEGMENT_ID_LENGTH];
} PrimaryValue_t;

typedef struct {
    uint8_t chunkFp[CHUNK_HASH_SIZE];
    RecipeEntry_t address;
} BinValue_t;

typedef struct {
    RecipeEntry_t address;
    uint32_t chunkFreq;
    uint32_t idx;
} HeapItem_t;

// ------------------------------------
// START for upload
// ------------------------------------

typedef struct {
    uint8_t dedupFlag; // true: for duplicate, false: for unique 
    uint8_t chunkHash[CHUNK_HASH_SIZE];
    uint8_t cloudContainerName[CONTAINER_ID_LENGTH];
    uint8_t edgeContainerName[CONTAINER_ID_LENGTH];
} OutQueryEntry_t; // returned by the outside application for query

typedef struct {
    uint32_t queryNum;
    OutQueryEntry_t* outQueryBase;
} OutQuery_t;

typedef struct {
    uint8_t dedupFlag; // true: for duplicate, false: for unique 
    uint8_t chunkHash[CHUNK_HASH_SIZE];
    uint8_t MLEKey[CHUNK_HASH_SIZE];
    uint8_t cloudContainerName[CONTAINER_ID_LENGTH];
    uint8_t edgeContainerName[CONTAINER_ID_LENGTH];
    uint32_t chunkFreq;
    uint32_t chunkSize;
    uint32_t entryOffset;
} InQueryEntry_t; // returned by the outside application for query

typedef struct {
    Container_t* curContainer;
    Recipe_t* outRecipe;
    Recipe_t* outUpRecipe;
    OutQuery_t* outQuery;
    void* outClient;
    void* sgxClient;
} UpOutSGX_t;

// ------------------------------------
// START for restore
// ------------------------------------

typedef struct {
    uint8_t edgeContainerName[CONTAINER_ID_LENGTH]; 
    uint8_t chunkHash[CHUNK_HASH_SIZE];
} OutRestoreEntry_t;

typedef struct {
    uint8_t chunkHash[CHUNK_HASH_SIZE];
    uint8_t mleKey[MLE_KEY_SIZE];
    uint8_t edgeContainerName[CONTAINER_ID_LENGTH]; 
    uint32_t containerID;
} InRestoreEntry_t;

typedef struct {
    uint8_t* idBuffer;
    uint8_t** containerArray;
    uint32_t idNum;
} ReqContainer_t;

typedef struct {
    ReqContainer_t* reqContainer;
    SendMsgBuffer_t* sendChunkBuf;
    OutRestoreEntry_t* outRestoreEntry;
    size_t *recipeNum;
    void* outClient; // the out-enclave client ptr
    void* sgxClient; // the sgx-client ptr
} ResOutSGX_t;

// ------------------------------------
// END for restore
// ------------------------------------

typedef struct _ra_msg4_struct {
    uint8_t status; // true: 1, false: 0
    //sgx_platform_info_t platformInfoBlob;
} ra_msg4_t;

typedef struct {
    uint8_t* secret;
    size_t length;
} DerivedKey_t;

#endif //BASICDEDUP_CHUNK_h