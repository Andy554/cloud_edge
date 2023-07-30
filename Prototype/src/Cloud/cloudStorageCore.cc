/**
 * @file storageCore.cc
 * @author Zuoru YANG (zryang@cse.cuhk.edu.hk)
 * @brief implement the interfaces defined in the storage core.
 * @version 0.1
 * @date 2019-12-27
 * 
 * @copyright Copyright (c) 2019
 * 
 */

#include "../../include/cloudStorageCore.h"


extern Configure config;

/**
 * @brief Construct a new Storage Core object
 * 
 */
CloudStorageCore::CloudStorageCore() {
    recipeNamePrefix_ = config.GetRecipeRootPath();
    recipeNameTail_ = config.GetRecipeSuffix();
}

/**
 * @brief Destroy the Storage Core:: Storage Core object
 * 
 */
CloudStorageCore::~CloudStorageCore() {
}

/**
 * @brief finalize the file recipe
 * 
 * @param recipeHead the recipe header
 * @param fileRecipeHandler the recipe file handler
 */
void CloudStorageCore::FinalizeRecipe(FileRecipeHead_t* recipeHead, 
    ofstream& fileRecipeHandler) {
    if (!fileRecipeHandler.is_open()) {
        tool::Logging(myName_.c_str(), "recipe file does not open.\n");
        exit(EXIT_FAILURE);
    }
    fileRecipeHandler.seekp(0, ios_base::beg);
    fileRecipeHandler.write((const char*)recipeHead, sizeof(FileRecipeHead_t));

    fileRecipeHandler.close();    
    return ; 
}

/**
 * @brief update the file recipe to the disk
 * 
 * @param recipeBuffer the pointer to the recipe buffer
 * @param recipeEntryNum the number of recipe entries
 * @param fileRecipeHandler the recipe file handler
 */
void CloudStorageCore::UpdateRecipeToFile(const uint8_t* recipeBuffer, size_t recipeEntryNum, 
    ofstream& fileRecipeHandler) {
    if (!fileRecipeHandler.is_open()) {
        tool::Logging(myName_.c_str(), "recipe file does not open.\n");
        exit(EXIT_FAILURE);
    }
    size_t recipeBufferSize = recipeEntryNum * sizeof(RecipeEntry_t);
    fileRecipeHandler.write((char*)recipeBuffer, recipeBufferSize);
    return ;
}

/**
* @brief update the file recipe to the disk (with MLE key version)
* 
* @param recipeBuffer the pointer to the recipe buffer
* @param recipeEntryNum the number of recipe entries
* @param fileRecipeHandler the recipe file handler
*/
void CloudStorageCore::UpdateRecipeToFileWithMLEKey(const uint8_t* recipeBuffer, size_t recipeEntryNum, 
    ofstream& fileRecipeHandler) {
    if (!fileRecipeHandler.is_open()) {
        tool::Logging(myName_.c_str(), "recipe file does not open.\n");
        exit(EXIT_FAILURE);
    }
    tool::Logging(myName_.c_str(), "write %lu recipes\n", recipeEntryNum);
    size_t recipeBufferSize = recipeEntryNum * CHUNK_HASH_SIZE;
    fileRecipeHandler.write((char*)recipeBuffer, recipeBufferSize);
    return ;
}

/**
 * @brief 将 CloudRecipe 写入到磁盘中。先写入 FileRecipeHead ，然后将 CloudRecipe 中的
 * entryList 转换成若干个 recipeBuffer ，并依次调用 UpdateRecipeToFile 将 RecipeEntry
 * 写入到磁盘中。
 * 
 * @param  cloudRecipe the cloud recipe     
 * @param  recipeHead the recipe header      
 * @param  fileRecipeHandler the recipe file handler
 */
void CloudStorageCore::FinalizeCloudRecipe(CloudRecipe_t* cloudRecipe, FileRecipeHead_t* recipeHead, ofstream& fileRecipeHandler, uint64_t recipeBatchSize){
    FinalizeRecipe(recipeHead, fileRecipeHandler);
    uint8_t* FpIdxEntryList = cloudRecipe->entryList;
    uint32_t chunkNum = cloudRecipe->recipeNum;
    uint8_t* recipeBuffer = (uint8_t*)malloc(sizeof(RecipeEntry_t) * recipeBatchSize);
    uint64_t recipeBufferOffset = 0;
    for (uint32_t i = 0; i < chunkNum; i++) {
        uint8_t* tmpChunkAddr = FpIdxEntryList + i * sizeof(FpIdxEntry_t)  
                            + CHUNK_HASH_SIZE; // 第 uniqueFpIdx 个 entry
        memcpy(recipeBuffer + recipeBufferOffset * sizeof(RecipeEntry_t), tmpChunkAddr, sizeof(RecipeEntry_t));
        recipeBufferOffset ++;
        if(recipeBufferOffset >= recipeBatchSize){
            UpdateRecipeToFile(recipeBuffer, recipeBatchSize, fileRecipeHandler);
            recipeBufferOffset = 0;
        }
    }
    if(recipeBufferOffset > 0){
        UpdateRecipeToFile(recipeBuffer, recipeBatchSize, fileRecipeHandler);
    }
    free(recipeBuffer);
    return ;
}

//TODO: 需修改
// 参考自 Prototype/src/Enclave/ocallSrc/storeOCall.cc 中的 WriteContainer()
void CloudStorageCore::WriteContainer(EdgeVar* outEdge){
#if (MULTI_CLIENT == 1) 
    dataWriterObj_->SaveToFile(outClientPtr->_curContainer);
#else
    outEdge->_inputMQ->Push(outEdge->_curContainer);
    printf("Write Cloud container: push container success.\n");
#endif
    // reset current container
    tool::CreateUUID(outEdge->_curContainer.containerID,
        CONTAINER_ID_LENGTH);
    outEdge->_curContainer.currentSize = 0;
    return ;
}

/**
 * @brief save the chunk to the storage serve
 * 
 * @param outEdge the edge ptr
 * @param chunkData the chunk data buffer
 * @param chunkSize the chunk size
 * @param chunkAddr the chunk address (return)
 */
void CloudStorageCore::SaveChunk(EdgeVar* outEdge, const char* chunkData, uint32_t chunkSize, RecipeEntry_t* chunkAddr){
    Container_t* curContainer = &outEdge->_curContainer;
    chunkAddr->length = chunkSize;
    uint32_t saveOffset = curContainer->currentSize;
    uint32_t writeOffset = saveOffset;
    if(saveOffset + chunkSize >= MAX_CONTAINER_SIZE){
        curContainer->currentSize = 0;
        WriteContainer(outEdge);
        saveOffset = 0;
        writeOffset = saveOffset;
    }
    memcpy(curContainer->body + writeOffset, chunkData, chunkSize);
    writeOffset += chunkSize;
    curContainer->currentSize = writeOffset;

    chunkAddr->offset = saveOffset;
    memcpy(chunkAddr->containerName , curContainer->containerID, CONTAINER_ID_LENGTH);
    /*
    writtenDataSize_ += chunkSize;
    writtenChunkNum_++;
    */
    return ;
}