#ifndef DATA_RECEIVER_H
#define DATA_RECEIVER_H

#include "configure.h"
#include "clientVar.h"
#include "edgeVar.h"
#include "sslConnection.h"
#include "absIndex.h"
#include "cloudStorageCore.h"

class CloudReceiver {
    private:
        string myName_ = "CloudReceiver";
        // for ssl connection
        SSLConnection* dataSecureChannel_;

        uint64_t batchNum_ = 0;
        uint64_t recipeEndNum_ = 0;

        // to pass the data to the index thread
        AbsIndex* absIndexObj_;

        // pass the storage core obj
        CloudStorageCore* storageCoreObj_;

    public:
        
        /**
         * @brief Construct a new DataReceiver object
         * 
         * @param absIndexObj the pointer to the index obj
         * @param dataSecurity the pointer to the security channel
         */
        CloudReceiver(AbsIndex* absIndexObj, SSLConnection* dataSecureChannel);
        

        /**
         * @brief Destroy the DataReceiver object
         * 
         */
        ~CloudReceiver();

        /**
         * @brief the main process to handle new edge upload-request connection
         * 
         * @param outEdge the edge ptr
         * @param cloudInfo the pointer to the cloud info 
         */
        void Run(EdgeVar* outEdge, CloudInfo_t* cloudInfo);


        /**
         * @brief Set the Storage Core Obj object
         * 
         * @param storageCoreObj the pointer to the storage core obj
         */
        void SetCloudStorageCoreObj(CloudStorageCore* storageCoreObj) {
            storageCoreObj_ = storageCoreObj;
            return ;
        }
};

#endif