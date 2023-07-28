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

void CloudStorageCore::WriteContainer(EdgeVar* outEdge){
#if (MULTI_CLIENT == 1) 
    dataWriterObj_->SaveToFile(outClientPtr->_curContainer);
#else
    outEdge->_inputMQ->Push(outEdge->_curContainer);
    printf("Ocall-write container: push container success.\n");
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
void CloudStorageCore::SaveChunk(EdgeVar* outEdge, char* chunkData, uint32_t chunkSize, RecipeEntry_t* chunkAddr){
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
    /*
    writtenDataSize_ += chunkSize;
    writtenChunkNum_++;
    */
    return ;
}