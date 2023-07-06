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

    sendEncBuffer_.sendBuffer = (uint8_t*) malloc(sizeof(NetworkHead_t) +
        sendChunkBatchSize_ * sizeof(Chunk_t));
    sendEncBuffer_.header = (NetworkHead_t*) sendEncBuffer_.sendBuffer;
    sendEncBuffer_.header->clientID = edgeID_;
    sendEncBuffer_.header->currentItemNum = 0;
    sendEncBuffer_.header->dataSize = 0;
    sendEncBuffer_.dataBuffer = sendEncBuffer_.sendBuffer + sizeof(NetworkHead_t);

    // prepare the crypto tool
    cryptoObj_ = new CryptoPrimitive(CIPHER_TYPE, HASH_TYPE);
    cipherCtx_ = EVP_CIPHER_CTX_new();
    mdCtx_ = EVP_MD_CTX_new();
    tool::Logging(myName_.c_str(), "init the Uploader.\n");
}

Uploader::~Uploader() {
    free(sendEncBuffer_.sendBuffer);
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

void Uploader::UploadLogin(string localSecret, uint8_t* fileNameHash) {
    // generate the hash of the master key
    uint8_t masterKey[CHUNK_HASH_SIZE];
    cryptoObj_->GenerateHash(mdCtx_, (uint8_t*)&localSecret[0], localSecret.size(),
        masterKey);

    // header + fileNameHash + Enc(masterKey)
    SendMsgBuffer_t msgBuf;
    msgBuf.sendBuffer = (uint8_t*) malloc(sizeof(NetworkHead_t) + 
        CHUNK_HASH_SIZE + CHUNK_HASH_SIZE);
    msgBuf.header = (NetworkHead_t*) msgBuf.sendBuffer;
    msgBuf.header->clientID = edgeID_;
    msgBuf.header->dataSize = 0;
    msgBuf.dataBuffer = msgBuf.sendBuffer + sizeof(NetworkHead_t);
    msgBuf.header->messageType = CLIENT_LOGIN_UPLOAD;

    memcpy(msgBuf.dataBuffer + msgBuf.header->dataSize, fileNameHash, 
        CHUNK_HASH_SIZE);
    msgBuf.header->dataSize += CHUNK_HASH_SIZE;
    cryptoObj_->SessionKeyEnc(cipherCtx_, masterKey, CHUNK_HASH_SIZE, 
        sessionKey_, msgBuf.dataBuffer + CHUNK_HASH_SIZE);
    msgBuf.header->dataSize += CHUNK_HASH_SIZE;

    // send the upload login request
    if (!dataSecureChannel_->SendData(conChannelRecord_.second, 
        msgBuf.sendBuffer, sizeof(NetworkHead_t) + msgBuf.header->dataSize)) {
        tool::Logging(myName_.c_str(), "send the edge upload login error.\n");
        exit(EXIT_FAILURE);
    }

    // wait the server to send the login response
    uint32_t recvSize = 0;
    if (!dataSecureChannel_->ReceiveData(conChannelRecord_.second, 
        msgBuf.sendBuffer, recvSize)) {
        tool::Logging(myName_.c_str(), "recv the cloud login response error.\n");
        exit(EXIT_FAILURE);
    }

    if (msgBuf.header->messageType == SERVER_LOGIN_RESPONSE) {
        tool::Logging(myName_.c_str(), "recv the cloud login response well, "
            "the cloud is ready to process the request.\n");
    } else {
        tool::Logging(myName_.c_str(), "cloud response is wrong, it is not ready.\n");
        exit(EXIT_FAILURE);
    }

    free(msgBuf.sendBuffer);
    return ;
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
                case CHUNK_FP: {
                    // this is a chunk fp
                    this->ProcessFp(tmpChunk.chunkHash);
                    break;
                }
                case FP_END: {
                    //this is the fps tail
                    this->ProcessFpEnd();
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
    sendChunkBuf_.header->messageType = CLIENT_UPLOAD_RECIPE_END;
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

//ljh add
void Uploader::ProcessFpEnd() {
    // first check the send fp buffer
    if (sendFpBuf_.header->currentItemNum != 0) {
        this->SendFps();
    }

    // send the fp end
    sendFpBuf_.header->messageType = UPLOAD_FP_END;
    if (!dataSecureChannel_->SendData(conChannelRecord_.second,
        sendFpBuf_.sendBuffer, sizeof(NetworkHead_t))) {
        tool::Logging(myName_.c_str(), "send the fp end error.\n");
        exit(EXIT_FAILURE);
    }
    return ;
}
void Uploader::ProcessFp(uint8_t* fp) {
    // update the send chunk buffer
    memcpy(sendFpBuf_.dataBuffer + sendFpBuf_.header->dataSize, fp, CHUNK_HASH_SIZE);
    sendFpBuf_.header->dataSize += CHUNK_HASH_SIZE;
    sendFpBuf_.header->currentItemNum++;
    if (sendFpBuf_.header->currentItemNum % sendChunkBatchSize_ == 0) { 
        this->SendFps();
    }
    return ;
}
void Uploader::SendFps() {
    sendFpBuf_.header->messageType = UPLOAD_FP;
    if (!dataSecureChannel_->SendData(conChannelRecord_.second, 
        sendFpBuf_.sendBuffer, 
        sizeof(NetworkHead_t) + sendFpBuf_.header->dataSize)) {
        tool::Logging(myName_.c_str(), "send the fp batch error.\n");
        exit(EXIT_FAILURE);
    }
    // clear the current chunk buffer
    sendFpBuf_.header->currentItemNum = 0;
    sendFpBuf_.header->dataSize = 0;
    return ;
}

/**
 * @brief send a batch of chunks
 * 
 * @param chunkBuffer the chunk buffer
 */
void Uploader::SendChunks() {
    sendChunkBuf_.header->messageType = CLIENT_UPLOAD_CHUNK;

    // encrypt the payload with the session key
    cryptoObj_->SessionKeyEnc(cipherCtx_, sendChunkBuf_.dataBuffer,
        sendChunkBuf_.header->dataSize, sessionKey_,
        sendEncBuffer_.dataBuffer);

    memcpy(sendEncBuffer_.header, sendChunkBuf_.header, 
        sizeof(NetworkHead_t));
    
    if (!dataSecureChannel_->SendData(conChannelRecord_.second, 
        sendEncBuffer_.sendBuffer, 
        sizeof(NetworkHead_t) + sendEncBuffer_.header->dataSize)) {
        tool::Logging(myName_.c_str(), "send the chunk batch error.\n");
        exit(EXIT_FAILURE);
    }
    
    // clear the current chunk buffer
    sendChunkBuf_.header->currentItemNum = 0;
    sendChunkBuf_.header->dataSize = 0;
    batchNum_++;

    return ;
}