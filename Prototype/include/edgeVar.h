/**
 * @file edgeVar.h
 * @author Zuoru YANG (zryang@cse.cuhk.edu.hk)
 * @brief define the class to store the variable related to a edge in the outside the enclave
 * @version 0.1
 * @date 2021-04-24
 * 
 * @copyright Copyright (c) 2021
 * 
 */

#ifndef EDGE_VAR_H
#define EDGE_VAR_H

#include "define.h"
#include "chunkStructure.h"
#include "messageQueue.h"
#include "readCache.h"
#include "sslConnection.h"

using namespace std;

extern Configure config;

class EdgeVar{
    private:
        string myName_ = "EdgeVar";
        int optType_; // the operation type (upload / download)
        string recipePath_;
        string upRecipePath_;
        
        /**
         * @brief init the upload buffer
         * 
         */
        void InitUploadBuffer();

        /**
         * @brief destroy the upload buffer
         * 
         */
        void DestroyUploadBuffer();

        /**
         * @brief init the restore buffer
         * 
         */
        void InitRestoreBuffer();

        /**
         * @brief destroy the restore buffer
         * 
         */
        void DestroyRestoreBuffer();
    public:
        uint32_t _edgeID;
        uint64_t sendChunkBatchSize_;
        uint64_t sendRecipeBatchSize_;

        // for handling file recipe
        ofstream _recipeWriteHandler;
        ofstream _upRecipeWriteHandler;
        ifstream _recipeReadHandler;
        string _tmpQueryBufferStr;

        // for sgx context 
        UpOutSGX_t _upOutSGX; // pass this structure to the enclave for upload
        ResOutSGX_t _resOutSGX; // pass this structure to the enclave for restore

        // upload buffer parameters
        Container_t _curContainer; // current container buffer
        OutQuery_t _outQuery; // the buffer to store the encrypted chunk fp
        MessageQueue<Container_t>* _inputMQ;
        SendMsgBuffer_t _recvChunkBuf; 
        SendMsgBuffer_t _recvFpBuf; 
        Recipe_t _outRecipe; // the buffer to store ciphertext recipe
        Recipe_t _outUpRecipe;
        CloudRecipe_t _cloudRecipe;

        // restore buffer parameters
        uint8_t* _readRecipeBuf;
        ReqContainer_t _reqContainer;
        ReadCache* _containerCache;
        SendMsgBuffer_t _sendChunkBuf;
        SendMsgBuffer_t _sendFpBoolBuf; //发送给edge的Fp bool数组
        OutRestoreEntry_t* _outRestoreEntry;
        size_t recipeNum;

        SSL* _edgeSSL; // connection

        uint64_t _uploadChunkNum = 0; 
        // upload logical data size
        uint64_t _uploadDataSize = 0;

        /**
         * @brief Construct a new EdgeVar object
         * 
         * @param edgeID the edge ID
         * @param edgeSSL the edge SSL
         * @param optType the operation type (upload / download)
         * @param recipePath the file recipe path
         */
        EdgeVar(uint32_t edgeID, SSL* edgeSSL, 
            int optType, /*string& recipePath, */string& upRecipePath);

        /**
         * @brief Destroy the Edge Var object
         * 
         */
        ~EdgeVar();
};

#endif