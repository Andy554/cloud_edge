#ifndef BASICDEDUP_CLOUD_STORAGECORE_h
#define BASICDEDUP_CLOUD_STORAGECORE_h

#include "configure.h"
#include "chunkStructure.h"
#include "messageQueue.h"
#include "absDatabase.h"
#include "dataWriter.h"
#include "define.h"
#include "edgeVar.h"
#include "storageCore.h"

#define NEW_FILE_NAME_HASH 1
#define OLD_FILE_NAME_HASH 2

using namespace std;

class CloudStorageCore : public StorageCore {
    private:
        string myName_ = "CloudStorageCore";
        std::string recipeNamePrefix_;
        std::string recipeNameTail_;
    public:
        /**
         * @brief finalize the file recipe
         * 
         * @param recipeHead the recipe header
         * @param fileRecipeHandler the recipe file handler
         */
        void FinalizeRecipe(FileRecipeHead_t* recipeHead, 
            ofstream& fileRecipeHandler);

        /**
         * @brief finalize the file recipe
         * 
         * @param recipeHead the recipe header
         * @param fileRecipeHandler the recipe file handler
         */
        void FinalizeUpRecipe(FileRecipeHead_t* recipeHead, 
            ofstream& fileRecipeHandler);

        /**
         * @brief 将 CloudRecipe 写入到磁盘中。先写入 FileRecipeHead ，然后将 CloudRecipe 中的
         * entryList 转换成若干个 recipeBuffer ，并依次调用 UpdateRecipeToFile 将 RecipeEntry
         * 写入到磁盘中。
         * 
         * @param  cloudRecipe the cloud recipe     
         * @param  recipeHead the recipe header      
         * @param  fileRecipeHandler the recipe file handler
         */
        void FinalizeCloudRecipe(CloudRecipe_t* cloudRecipe, FileRecipeHead_t* recipeHead, 
            ofstream& fileRecipeHandler, uint64_t recipeBatchSize);

        /**
         * @brief update the file recipe to the disk
         * 
         * @param recipeBuffer the pointer to the recipe buffer
         * @param recipeEntryNum the number of recipe entries
         * @param fileRecipeHandler the recipe file handler
         */
        void UpdateRecipeToFile(const uint8_t* recipeBuffer, size_t recipeEntryNum, ofstream& fileRecipeHandler);

        /**
         * @brief update the file recipe to the disk (with MLE key version)
         * 
         * @param recipeBuffer the pointer to the recipe buffer
         * @param recipeEntryNum the number of recipe entries
         * @param fileRecipeHandler the recipe file handler
         */
        void UpdateRecipeToFileWithMLEKey(const uint8_t* recipeBuffer, size_t recipeEntryNum, ofstream& fileRecipeHandler);

        /**
         * @brief write the container to the disk and assign a new container
         * 
         * @param outEdge the edge ptr
         */
        void WriteContainer(EdgeVar* outEdge);

        /**
         * @brief save the chunk to the storage serve
         * 
         * @param outEdge the edge ptr
         * @param chunkData the chunk data buffer
         * @param chunkSize the chunk size
         * @param chunkAddr the chunk address (return)
         */
        void SaveChunk(EdgeVar* outEdge, char* chunkData, uint32_t chunkSize, RecipeEntry_t* chunkAddr);

        /**
         * @brief Construct a new Storage Core object
         * 
         */
        CloudStorageCore();
        
        /**
         * @brief Destroy the Storage Core object
         * 
         */
        ~CloudStorageCore();
};


#endif // !BASICDEDUP_CLOUD_STORAGECORE_h
