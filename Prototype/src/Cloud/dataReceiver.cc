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
 * @param dataSecureChannel the pointer to the security channel
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
    UpOutSGX_t* upOutSGX = &outEdge->_upOutSGX; // 整理后传到 enclave，cloud 虽然没有 enclave，但是传入精简的结构体会不会减少开销
    SendMsgBuffer_t* recvChunkBuf = &outEdge->_recvChunkBuf;
    Container_t* curContainer = &outEdge->_curContainer;
    SSL* edgeSSL = outEdge->_edgeSSL;
    
    struct timeval sProcTime;
    struct timeval eProcTime;
    double totalProcessTime = 0;

    tool::Logging(myName_.c_str(), "the main thread is running.\n");
    bool end = false;
    while (!end) {
        // receive fp 
        if (!dataSecureChannel_->ReceiveData(edgeSSL, recvFpBuf->sendBuffer, 
            recvSize)) {
            tool::Logging(myName_.c_str(), "edge closed socket connect, thread exit now.\n");
            dataSecureChannel_->GetClientIp(edgeIP, edgeSSL);
            dataSecureChannel_->ClearAcceptedClientSd(edgeSSL);
            break;
        } else {
            gettimeofday(&sProcTime, NULL);
            switch (recvFpBuf->header->messageType) { // recvFpBuf->header->messageType
                case EDGE_UPLOAD_FP: {// 新增，服务器上传指纹，我们先返回指纹是否存在，然后才上传 chunk
                    // TODO:每处理一个fp batch，就将bool数组发给edge
                    absIndexObj_->ProcessFpOneBatch(recvFpBuf, upOutSGX); 
                    break;
                }
                case EDGE_UPLOAD_FP_END: {// 服务器上传最后一批指纹
                    // TODO：处理最后一个fp batch，并且将得到的bool数组发回edge
                    absIndexObj_->ProcessFpTailBatch(upOutSGX); 
                    /*
                    SendMsgBuffer_t FpBoolBuf;
                    FpBoolBuf.sendBuffer = (uint8_t*) malloc(sizeof(NetworkHead_t) + 
                    FpNum );
                    msgBuf.header = (NetworkHead_t*) msgBuf.sendBuffer;
                    msgBuf.header->clientID = edgeID_;
                    msgBuf.header->dataSize = 0;
                    msgBuf.dataBuffer = msgBuf.sendBuffer + sizeof(NetworkHead_t);
                    msgBuf.header->messageType = EDGE_LOGIN_UPLOAD;


                    if (!dataSecureChannel_->SendData(edgeSSL, recvBuf.sendBuffer,
                        sizeof(NetworkHead_t))) {
                        tool::Logging(myName_.c_str(), "send the file not exist reply error.\n");
                        exit(EXIT_FAILURE);
                    }
                    */
                    end = true;
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
    /*
    while (true) {
        // receive data 
        if (!dataSecureChannel_->ReceiveData(edgeSSL, recvChunkBuf->sendBuffer, 
            recvSize)) {
            tool::Logging(myName_.c_str(), "edge closed socket connect, thread exit now.\n");
            dataSecureChannel_->GetClientIp(edgeIP, edgeSSL);
            dataSecureChannel_->ClearAcceptedClientSd(edgeSSL);
            break;
        } else {
            gettimeofday(&sProcTime, NULL);
            switch (recvChunkBuf->header->messageType) { // recvFpBuf->header->messageType
                case EDGE_UPLOAD_CHUNK: {
                    absIndexObj_->ProcessOneBatch(recvChunkBuf, upOutSGX); // ? chunk 存 recvChunkBuf
                    batchNum_++;
                    break;
                }
                case EDGE_UPLOAD_CHUNK_END: {
                    // this is the end of one upload 
                    absIndexObj_->ProcessTailBatch(upOutSGX);
                    // finalize the file recipe
                    storageCoreObj_->FinalizeRecipe((FileRecipeHead_t*)recvChunkBuf->dataBuffer,
                        outEdge->_recipeWriteHandler); // 写入 file recipe 信息 fileSize and totalChunkNum
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
    */
    tool::Logging(myName_.c_str(), "thread exit for %s, ID: %u, enclave total process time: %lf\n", 
        edgeIP.c_str(), outEdge->_edgeID, totalProcessTime);

    cloudinfo->enclaveProcessTime = totalProcessTime;
    // Ecall_GetEnclaveInfo(eidSGX_, cloudinfo); // 获取 sgx_info 这里不用吧?
    return ;
}