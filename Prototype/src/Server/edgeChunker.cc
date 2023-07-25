#include "../../include/edgeChunker.h"



EdgeChunker::EdgeChunker(SSLConnection* sslConnection,
    sgx_enclave_id_t eidSGX) : AbsRecvDecoder(sslConnection) {
    isInCloud = (bool*)malloc(sendRecipeBatchSize_ * sizeof(bool));
    eidSGX_ = eidSGX;
    Ecall_Init_Restore(eidSGX_);
    tool::Logging(myName_.c_str(), "init the EdgeChunker.\n");
}


EdgeChunker::~EdgeChunker() {
    fprintf(stderr, "========EdgeChunker Info========\n");
    fprintf(stderr, "read container from file num: %lu\n", readFromContainerFileNum_);
    fprintf(stderr, "=======================================\n");
    free(isInCloud);
}

/**
 * @brief the main process
 * 
 * @param outClient the out-enclave client ptr
 */
void EdgeChunker::Run(ClientVar* outClient) {
    tool::Logging(myName_.c_str(), "the main thread is running.\n");
    SSL* clientSSL = outClient->_clientSSL;
    ResOutSGX_t* resOutSGX = &outClient->_resOutSGX;

    uint8_t* readRecipeBuf = outClient->_readRecipeBuf;
    SendMsgBuffer_t* sendChunkBuf = &outClient->_sendChunkBuf;
    uint32_t recvSize = 0;

    struct timeval sProcTime;
    struct timeval eProcTime;
    double totalProcTime = 0;
    tool::Logging(myName_.c_str(), "start to read the file recipe.\n");
    gettimeofday(&sProcTime, NULL);
    bool end = false;
    tool::Logging(myName_.c_str(), "sendRecipeBatchSize: %lu.\n", sendRecipeBatchSize_);
    while (!end) {
        if (!dataSecureChannel_->ReceiveData(clientSSL, (uint8_t*)isInCloud, recvSize)) {
            tool::Logging(myName_.c_str(), "receive cloud isInCloud fail.\n");
            exit(EXIT_FAILURE);
        }
        // read a batch of the recipe entries from the recipe file
        outClient->_recipeReadHandler.read((char*)readRecipeBuf, 
            CHUNK_HASH_SIZE * sendRecipeBatchSize_);
        size_t readCnt = outClient->_recipeReadHandler.gcount();
        end = outClient->_recipeReadHandler.eof();
        size_t recipeEntryNum = readCnt / CHUNK_HASH_SIZE;
        
        if (readCnt == 0) {
            break;
        }

        totalRestoreRecipeNum_ += recipeEntryNum;
        Ecall_ProcRecipeBatchForEdgeUpload(eidSGX_, readRecipeBuf, recipeEntryNum, 
            resOutSGX, isInCloud);
    }

    Ecall_ProcRecipeTailBatchForEdgeUpload(eidSGX_, resOutSGX);
    
    gettimeofday(&eProcTime, NULL);
    totalProcTime += tool::GetTimeDiff(sProcTime, eProcTime);

    return ;
}
