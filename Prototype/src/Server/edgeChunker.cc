#include "../../include/edgeChunker.h"



EdgeChunker::EdgeChunker(SSLConnection* sslConnection,
    sgx_enclave_id_t eidSGX, bool* _isInCloud) : AbsRecvDecoder(sslConnection) {
    isInCloud = _isInCloud;
    eidSGX_ = eidSGX;
    Ecall_Init_Restore(eidSGX_);
    tool::Logging(myName_.c_str(), "init the EdgeChunker.\n");
}


EdgeChunker::~EdgeChunker() {
    fprintf(stderr, "========EdgeChunker Info========\n");
    fprintf(stderr, "read container from file num: %lu\n", readFromContainerFileNum_);
    fprintf(stderr, "=======================================\n");
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
    uint32_t offset = 0;
    tool::Logging(myName_.c_str(), "sendRecipeBatchSize: %lu.\n", sendRecipeBatchSize_);
    while (!end) {
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
        tool::Logging(myName_.c_str(), "recipe entry num: %lu, ready to restore a batch.\n", recipeEntryNum);
        Ecall_ProcRecipeBatchForEdgeUpload(eidSGX_, readRecipeBuf, recipeEntryNum, 
            resOutSGX, isInCloud + offset);
        offset += recipeEntryNum;
    }

    Ecall_ProcRecipeTailBatchForEdgeUpload(eidSGX_, resOutSGX);
    
    gettimeofday(&eProcTime, NULL);
    totalProcTime += tool::GetTimeDiff(sProcTime, eProcTime);

    return ;
}

/**
 * @brief Get the Required Containers object 
 * 
 * @param outClient the out-enclave client ptr
 */
void EdgeChunker::GetReqContainers(ClientVar* outClient) {
    ReqContainer_t* reqContainer = &outClient->_reqContainer;
    uint8_t* idBuffer = reqContainer->idBuffer; 
    uint8_t** containerArray = reqContainer->containerArray;
    ReadCache* containerCache = outClient->_containerCache;
    uint32_t idNum = reqContainer->idNum; 

    // retrieve each container
    string containerNameStr;
    for (size_t i = 0; i < idNum; i++) {
        containerNameStr.assign((char*) (idBuffer + i * CONTAINER_ID_LENGTH), 
            CONTAINER_ID_LENGTH);
        // step-1: check the container cache
        bool cacheHitStatus = containerCache->ExistsInCache(containerNameStr);
        if (cacheHitStatus) {
            // step-2: exist in the container cache, read from the cache, directly copy the data from the cache
            memcpy(containerArray[i], containerCache->ReadFromCache(containerNameStr), 
                MAX_CONTAINER_SIZE);
            continue ;
        } 

        // step-3: not exist in the contain cache, read from disk
        ifstream containerIn;
        string readFileNameStr = containerNamePrefix_ + containerNameStr + containerNameTail_;
        containerIn.open(readFileNameStr, ifstream::in | ifstream::binary);

        if (!containerIn.is_open()) {
            tool::Logging(myName_.c_str(), "cannot open the container: %s\n", readFileNameStr.c_str());
            exit(EXIT_FAILURE);
        }

        // get the data section size (total chunk size - metadata section)
        containerIn.seekg(0, ios_base::end);
        int readSize = containerIn.tellg();
        containerIn.seekg(0, ios_base::beg);

        tool::Logging(myName_.c_str(), "container size: %d\n", readSize);

        // read the metadata section
        int containerSize = 0;
        containerSize = readSize;
        // read compression data
        containerIn.read((char*)containerArray[i], containerSize);

        if (containerIn.gcount() != containerSize) {
            tool::Logging(myName_.c_str(), "read size %lu cannot match expected size: %d for container %s.\n",
                containerIn.gcount(), containerSize, readFileNameStr.c_str());
            exit(EXIT_FAILURE);
        } 

        // close the container file
        containerIn.close();
        readFromContainerFileNum_++;
        containerCache->InsertToCache(containerNameStr, containerArray[i], containerSize);
    }
    return ;
}

/**
 * @brief send the restore chunk to the client
 * 
 * @param sendChunkBuf the send chunk buffer
 * @param clientSSL the ssl connection
 */
void EdgeChunker::SendBatchChunks(SendMsgBuffer_t* sendChunkBuf, 
    SSL* clientSSL) {
    if (!dataSecureChannel_->SendData(clientSSL, sendChunkBuf->sendBuffer, 
        sizeof(NetworkHead_t) + sendChunkBuf->header->dataSize)) {
        tool::Logging(myName_.c_str(), "send the batch of restored chunks error.\n");
        exit(EXIT_FAILURE);
    }
    return ;
}