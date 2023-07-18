/**
 * @file dataReceiver.cc
 * @author Zuoru YANG (zryang@cse.cuhk.edu.hk)
 * @brief implement the interface of data receivers 
 * @version 0.1
 * @date 2021-01-27
 * 
 * @copyright Copyright (c) 2021
 * 
 */

#include "../../include/dataReceiver.h"


/**
 * @brief Construct a new DataReceiver object
 * 
 * @param absIndexObj the pointer to the index obj
 * @param dataSecurity the pointer to the security channel
 * @param eidSGX the sgx id
 */
DataReceiver::DataReceiver(AbsIndex* absIndexObj, SSLConnection* dataSecureChannel) {
    // set up the connection and interface
    dataSecureChannel_ = dataSecureChannel;
    absIndexObj_ = absIndexObj;
    tool::Logging(myName_.c_str(), "init the DataReceiver.\n");
}

/**
 * @brief Destroy the DataReceiver object
 * 
 */
DataReceiver::~DataReceiver() {
    fprintf(stderr, "========DataReceiver Info========\n");
    fprintf(stderr, "total receive batch num: %lu\n", batchNum_);
    fprintf(stderr, "total receive recipe end num: %lu\n", recipeEndNum_);
    fprintf(stderr, "=================================\n");
}

/**
 * @brief the main process to handle new edge upload-request connection
 * 
 * @param outEdge the edge ptr
 * @param cloudinfo the pointer to the cloud info
 */
void DataReceiver::Run(EdgeVar* outEdge, CloudInfo_t* cloudInfo) {
    uint32_t recvSize = 0;
    string edgeIP;
    UpOutSGX_t* upOutSGX = &outEdge->_upOutSGX;
    SendMsgBuffer_t* recvChunkBuf = &outEdge->_recvChunkBuf;
    Container_t* curContainer = &outEdge->_curContainer;
    SSL* edgeSSL = outEdge->_edgeSSL;
    
    struct timeval sProcTime;
    struct timeval eProcTime;
    double totalProcessTime = 0;

    tool::Logging(myName_.c_str(), "the main thread is running.\n");
    while (true) {
        // receive data 
        if (!dataSecureChannel_->ReceiveData(edgeSSL, recvChunkBuf->sendBuffer, 
            recvSize)) {
            tool::Logging(myName_.c_str(), "edge closed socket connect, thread exit now.\n");
            dataSecureChannel_->GetEdgeIp(edgeIP, edgeSSL);
            dataSecureChannel_->ClearAcceptedEdgeSd(edgeSSL);
            break;
        } else {
            gettimeofday(&sProcTime, NULL);
            switch (recvChunkBuf->header->messageType) {
                case CLIENT_UPLOAD_CHUNK: {
                    absIndexObj_->ProcessOneBatch(recvChunkBuf, upOutSGX); 
                    batchNum_++;
                    break;
                }
                case CLIENT_UPLOAD_RECIPE_END: {
                    // this is the end of one upload 
                    absIndexObj_->ProcessTailBatch(upOutSGX);
                    // finalize the file recipe
                    storageCoreObj_->FinalizeRecipe((FileRecipeHead_t*)recvChunkBuf->dataBuffer,
                        outEdge->_recipeWriteHandler);
                    recipeEndNum_++;

                    // update the upload data size
                    FileRecipeHead_t* tmpRecipeHead = (FileRecipeHead_t*)recvChunkBuf->dataBuffer;
                    outEdge->_uploadDataSize = tmpRecipeHead->fileSize;
                    break;
                }
                default: {
                    // receive the wrong message type
                    tool::Logging(myName_.c_str(), "wrong received message type.\n");
                    exit(EXIT_FAILURE);
                }
            }
            gettimeofday(&eProcTime, NULL);
            totalProcessTime += tool::GetTimeDiff(sProcTime, eProcTime);
        }
    }

    // process the last container 
    if (curContainer->currentSize != 0) {
        Ocall_WriteContainer(outEdge);
    }
    outEdge->_inputMQ->done_ = true;
    tool::Logging(myName_.c_str(), "thread exit for %s, ID: %u, enclave total process time: %lf\n", 
        edgeIP.c_str(), outEdge->_edgeID, totalProcessTime);

    cloudinfo->enclaveProcessTime = totalProcessTime;
    Ecall_GetEnclaveInfo(eidSGX_, cloudinfo);
    return ;
}