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

#include "../../include/cloudReceiver.h"


/**
 * @brief Construct a new DataReceiver object
 * 
 * @param absIndexObj the pointer to the index obj
 * @param dataSecureChannel the pointer to the security channel
 */
CloudReceiver::CloudReceiver(AbsIndex* absIndexObj, SSLConnection* dataSecureChannel) {
    // set up the connection and interface
    dataSecureChannel_ = dataSecureChannel;
    absIndexObj_ = absIndexObj;
    tool::Logging(myName_.c_str(), "init the DataReceiver.\n");
}

/**
 * @brief Destroy the DataReceiver object
 * 
 */
CloudReceiver::~CloudReceiver() {
    fprintf(stderr, "========DataReceiver Info========\n");
    fprintf(stderr, "total receive batch num: %lu\n", batchNum_);
    fprintf(stderr, "total receive recipe end num: %lu\n", recipeEndNum_);
    fprintf(stderr, "=================================\n");
}

/**
 * @brief the main process to handle new edge upload-request connection
 * 
 * @param outEdge the edge ptr
 * @param cloudInfo the pointer to the cloud info
 */
void CloudReceiver::Run(EdgeVar* outEdge, CloudInfo_t* cloudInfo) {
    uint32_t recvSize = 0;
    uint64_t uploadChunkNum = outEdge->_uploadChunkNum; //得到edge发送的FP数量
    string edgeIP;
    UpOutSGX_t* upOutSGX = &outEdge->_upOutSGX; // 整理后传到 enclave，cloud 虽然没有 enclave，但是传入精简的结构体会不会减少开销
    SendMsgBuffer_t* recvChunkBuf = &outEdge->_recvChunkBuf;
    SendMsgBuffer_t* recvFpBuf = &outEdge->_recvFpBuf;
    SendMsgBuffer_t* sendFpBoolBuf = &outEdge->_sendFpBoolBuf;
    Container_t* curContainer = &outEdge->_curContainer;
    SSL* edgeSSL = outEdge->_edgeSSL;
    
    struct timeval sProcTime;
    struct timeval eProcTime;
    double totalProcessTime = 0;

    tool::Logging(myName_.c_str(), "the main thread is running.\n");

    // 查询 FP 是否存在结果的 message，除了 bool 结果，都是可以复用的
    sendFpBoolBuf->header->messageType = CLOUD_FP_RESPONSE; //暂不考虑接受来自edge的Fps存在的问题

    bool end = false;
    RecipeEntry_1_t* fp2CidArr = (RecipeEntry_1_t*) malloc(uploadChunkNum * sizeof(RecipeEntry_1_t));
    uint64_t fpCurNum = 0;

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
            switch (recvFpBuf->header->messageType) { 
                case EDGE_UPLOAD_FP: {// 新增，服务器上传指纹，我们先返回指纹是否存在，然后才上传 chunk
                    // TODO:每处理一个fp batch，就将bool数组发给edge
                    // ? 每次处理完就发回 edge，是否不必区分 FP_END
                    tool::Logging(myName_.c_str(), "start to process fp one batch...\n");
                    absIndexObj_->ProcessFpOneBatch(recvFpBuf, sendFpBoolBuf, fp2CidArr, fpCurNum);
                    // 类似 Client/dataSender.cc -> ProcessRecipeEnd() or SendChunks()
                    // 前者不加密；后者加密；当前不加密
                    if (!dataSecureChannel_->SendData(edgeSSL, sendFpBoolBuf->sendBuffer, sizeof(NetworkHead_t) + sendFpBoolBuf->header->dataSize)) {
                        tool::Logging(myName_.c_str(), "send the file not exist reply error.\n");
                        exit(EXIT_FAILURE);
                    }
                    break;
                }
                case EDGE_UPLOAD_FP_END: {// 服务器上传最后一批指纹
                    // TODO：处理最后一个fp batch，并且将得到的bool数组发回edge
                    tool::Logging(myName_.c_str(), "start to process fp tail batch...\n");
                    absIndexObj_->ProcessFpTailBatch(recvFpBuf, sendFpBoolBuf, fp2CidArr, fpCurNum); 
                    if (!dataSecureChannel_->SendData(edgeSSL, sendFpBoolBuf->sendBuffer, sizeof(NetworkHead_t) + sendFpBoolBuf->header->dataSize)) {
                        tool::Logging(myName_.c_str(), "send the file not exist reply error.\n");
                        exit(EXIT_FAILURE);
                    }
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
                    tool::Logging(myName_.c_str(), "start to process chunk one batch...\n");
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
                    tool::Logging(myName_.c_str(), "finish process chunk tail batch...====================\n");

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
        tool::Logging(myName_.c_str(), "start to write last container\n"); 
        Ocall_WriteContainer(outEdge);
        tool::Logging(myName_.c_str(), "write last container success\n");
    }
    outEdge->_inputMQ->done_ = true; 
    */
    tool::Logging(myName_.c_str(), "thread exit for %s, ID: %u, enclave total process time: %lf\n", 
        edgeIP.c_str(), outEdge->_edgeID, totalProcessTime);

    cloudInfo->enclaveProcessTime = totalProcessTime;
    // Ecall_GetEnclaveInfo(eidSGX_, cloudInfo); // 获取 sgx_info 这里不用吧?
    return ;
}