#include "../../include/uploader.h"

Uploader::Uploader(SSLConnection* dataSecureChannel){
    // set up the configuration
    edgeID_ = config.GetClientID();
    sendChunkBatchSize_ = config.GetSendChunkBatchSize();
    sendRecipeBatchSize_ = config.GetSendRecipeBatchSize();
    dataSecureChannel_ = dataSecureChannel;
    
    // init the send chunk buffer: header + <chunkSize, chunk content>
    sendChunkBuf_.sendBuffer = (uint8_t*) malloc(sizeof(NetworkHead_t) +
        sendChunkBatchSize_ * sizeof(Chunk_t));
    sendChunkBuf_.header = (NetworkHead_t*) sendChunkBuf_.sendBuffer;
    sendChunkBuf_.header->clientID = edgeID_;
    sendChunkBuf_.header->currentItemNum = 0;
    sendChunkBuf_.header->dataSize = 0;
    sendChunkBuf_.dataBuffer = sendChunkBuf_.sendBuffer + sizeof(NetworkHead_t);

    //init the send fp buffer
    sendFpBuf_.sendBuffer = (uint8_t*) malloc(sizeof(NetworkHead_t) +
        sendRecipeBatchSize_ * CHUNK_HASH_SIZE);
    sendFpBuf_.header = (NetworkHead_t*) sendFpBuf_.sendBuffer;
    sendFpBuf_.header->clientID = edgeID_;
    sendFpBuf_.header->currentItemNum = 0;
    sendFpBuf_.header->dataSize = 0;
    sendFpBuf_.dataBuffer = sendFpBuf_.sendBuffer + sizeof(NetworkHead_t);

    // prepare the crypto tool
    cryptoObj_ = new CryptoPrimitive(CIPHER_TYPE, HASH_TYPE);
    cipherCtx_ = EVP_CIPHER_CTX_new();
    mdCtx_ = EVP_MD_CTX_new();
    tool::Logging(myName_.c_str(), "init the Uploader.\n");
}

Uploader::~Uploader() {
    free(sendChunkBuf_.sendBuffer);
    free(sendFpBuf_.sendBuffer);
    EVP_CIPHER_CTX_free(cipherCtx_);
    EVP_MD_CTX_free(mdCtx_);
    delete cryptoObj_;
    fprintf(stderr, "========Uploader Info========\n");
    fprintf(stderr, "total send batch num: %lu\n", batchNum_);
    fprintf(stderr, "total thread running time: %lf\n", totalTime_);
    fprintf(stderr, "===============================\n");
}

void Uploader::UploadFileUpRecipe(uint8_t* fileNameHash) {
    char fileHashBuf[CHUNK_HASH_SIZE * 2 + 1];
    for (uint32_t i = 0; i < CHUNK_HASH_SIZE; i++) {
        sprintf(fileHashBuf + i * 2, "%02x", fileNameHash[i]);
    }
    string fileName;
    fileName.assign(fileHashBuf, CHUNK_HASH_SIZE * 2);
    string upRecipePath = config.GetUpRecipeRootPath() + fileName + config.GetRecipeSuffix();
    recipeReadHandler.open(upRecipePath, ios_base::in | ios_base::binary);
    if (!recipeReadHandler.is_open()) {
        tool::Logging(myName_.c_str(), "cannot init the file recipe: %s.\n",
            upRecipePath.c_str());
        exit(EXIT_FAILURE);
    }
    //header + fileNameHash + recipeHead
    SendMsgBuffer_t msgBuf;
    msgBuf.sendBuffer = (uint8_t*) malloc(sizeof(NetworkHead_t) + 
        CHUNK_HASH_SIZE + sizeof(FileRecipeHead_t));
    msgBuf.header = (NetworkHead_t*) msgBuf.sendBuffer;
    msgBuf.header->clientID = edgeID_;
    msgBuf.header->dataSize = 0;
    msgBuf.dataBuffer = msgBuf.sendBuffer + sizeof(NetworkHead_t);
    msgBuf.header->messageType = EDGE_LOGIN_UPLOAD;
    memcpy(msgBuf.dataBuffer + msgBuf.header->dataSize, fileNameHash, 
        CHUNK_HASH_SIZE);
    msgBuf.header->dataSize += CHUNK_HASH_SIZE;
    recipeReadHandler.read((char*)msgBuf.dataBuffer + msgBuf.header->dataSize,
        sizeof(FileRecipeHead_t));
    msgBuf.header->dataSize += sizeof(FileRecipeHead_t);
    if (!dataSecureChannel_->SendData(conChannelRecord_.second, 
        msgBuf.sendBuffer, sizeof(NetworkHead_t) + msgBuf.header->dataSize)) {
        tool::Logging(myName_.c_str(), "send the edge upload login error.\n");
        exit(EXIT_FAILURE);
    }
    free(msgBuf.sendBuffer);

    sendFpBuf_.header->messageType = EDGE_UPLOAD_FP;
    sendFpBuf_.header->clientID = edgeID_;
    bool end = false;
    while(!end){
        recipeReadHandler.read((char*)sendFpBuf_.dataBuffer, CHUNK_HASH_SIZE * sendRecipeBatchSize_);
        uint32_t readCnt = recipeReadHandler.gcount();
        if (readCnt == 0) {
            break;
        }
        sendFpBuf_.header->dataSize = readCnt;
        end = recipeReadHandler.eof();
        sendFpBuf_.header->currentItemNum = readCnt / CHUNK_HASH_SIZE;
        if(sendFpBuf_.header->currentItemNum < sendRecipeBatchSize_){
            sendFpBuf_.header->messageType = EDGE_UPLOAD_FP_END;
        }
        if (!dataSecureChannel_->SendData(conChannelRecord_.second, sendFpBuf_.sendBuffer, 
                sizeof(NetworkHead_t) + readCnt)) {
                tool::Logging(myName_.c_str(), "send the recipe batch error.\n");
                exit(EXIT_FAILURE);
        }
    }

}

void Uploader::Run() {
    bool jobDoneFlag = false;
    Data_t tmpChunk;
    struct timeval sTotalTime;
    struct timeval eTotalTime;

    tool::Logging(myName_.c_str(), "the main thread is running.\n");
    gettimeofday(&sTotalTime, NULL);
    while (true) {
        // the main loop
        if (inputMQ_->done_ && inputMQ_->IsEmpty()) {
            jobDoneFlag = true;
        }

        if (inputMQ_->Pop(tmpChunk)) {
            switch (tmpChunk.dataType) {
                case DATA_CHUNK: {
                    // this is a normal chunk
                    this->ProcessChunk(tmpChunk.chunk);
                    break;
                }
                case RECIPE_END: {
                    // this is the recipe tail
                    this->ProcessRecipeEnd(tmpChunk.recipeHead);

                    // close the connection
                    dataSecureChannel_->Finish(conChannelRecord_);
                    break;
                }
                default: {
                    tool::Logging(myName_.c_str(), "wrong data type.\n");
                    exit(EXIT_FAILURE);
                }
            }
        }
        if (jobDoneFlag) {
            break;
        }
    }

    gettimeofday(&eTotalTime, NULL);
    totalTime_ += tool::GetTimeDiff(sTotalTime, eTotalTime);
    tool::Logging(myName_.c_str(), "thread exit.\n");
    return ;
}

void Uploader::ProcessRecipeEnd(FileRecipeHead_t& recipeHead) {
    // first check the send chunk buffer
    if (sendChunkBuf_.header->currentItemNum != 0) {
        this->SendChunks();
    }

    // send the recipe end (without session encryption)
    sendChunkBuf_.header->messageType = EDGE_UPLOAD_CHUNK_END;
    sendChunkBuf_.header->dataSize = sizeof(FileRecipeHead_t);
    memcpy(sendChunkBuf_.dataBuffer, &recipeHead,
        sizeof(FileRecipeHead_t));
    if (!dataSecureChannel_->SendData(conChannelRecord_.second,
        sendChunkBuf_.sendBuffer, 
        sizeof(NetworkHead_t) + sendChunkBuf_.header->dataSize)) {
        tool::Logging(myName_.c_str(), "send the recipe end error.\n");
        exit(EXIT_FAILURE);
    }
    return ;
}

/**
 * @brief process a chunk
 * 
 * @param inputChunk the input chunk
 */
void Uploader::ProcessChunk(Chunk_t& inputChunk) {
    // update the send chunk buffer
    memcpy(sendChunkBuf_.dataBuffer + sendChunkBuf_.header->dataSize,
        &inputChunk.chunkSize, sizeof(uint32_t));
    sendChunkBuf_.header->dataSize += sizeof(uint32_t);
    memcpy(sendChunkBuf_.dataBuffer + sendChunkBuf_.header->dataSize,
        inputChunk.data, inputChunk.chunkSize);
    sendChunkBuf_.header->dataSize += inputChunk.chunkSize;
    sendChunkBuf_.header->currentItemNum++;

    if (sendChunkBuf_.header->currentItemNum % sendChunkBatchSize_ == 0) {
        this->SendChunks();
    }
    return ;
}

/**
 * @brief send a batch of chunks
 * 
 * @param chunkBuffer the chunk buffer
 */
void Uploader::SendChunks() {
    sendChunkBuf_.header->messageType = EDGE_UPLOAD_CHUNK;
  
    if (!dataSecureChannel_->SendData(conChannelRecord_.second, 
        sendChunkBuf_.sendBuffer, 
        sizeof(NetworkHead_t) + sendChunkBuf_.header->dataSize)) {
        tool::Logging(myName_.c_str(), "send the chunk batch error.\n");
        exit(EXIT_FAILURE);
    }
    
    // clear the current chunk buffer
    sendChunkBuf_.header->currentItemNum = 0;
    sendChunkBuf_.header->dataSize = 0;
    batchNum_++;
    return ;
}