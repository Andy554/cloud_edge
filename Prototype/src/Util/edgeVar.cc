/**
 * @file edgeVar.cc
 * @author Zuoru YANG (zryang@cse.cuhk.edu.hk)
 * @brief implement the interface of edge var
 * @version 0.1
 * @date 2021-04-24
 * 
 * @copyright Copyright (c) 2021
 * 
 */

#include "../../include/edgeVar.h"

/**
 * @brief Construct a new EdgeVar object
 * 
 * @param edgeID the edge ID
 * @param edgeSSL the edge SSL
 * @param optType the operation type (upload / download)
 * @param recipePath the file recipe path
 */
EdgeVar::EdgeVar(uint32_t edgeID, SSL* edgeSSL, 
    int optType, string& upRecipePath){
    // basic info
    _edgeID = edgeID;
    _edgeSSL = edgeSSL;
    optType_ = optType;
    upRecipePath_ = upRecipePath;
    myName_ = myName_ + "-" + to_string(_edgeID);

    // config
    sendChunkBatchSize_ = config.GetSendChunkBatchSize();
    sendRecipeBatchSize_ = config.GetSendRecipeBatchSize();

    switch (optType_) {
        case UPLOAD_OPT: {
            this->InitUploadBuffer();
            break;
        }
        case DOWNLOAD_OPT: {
            this->InitRestoreBuffer();
            break;
        }
        default: {
            tool::Logging(myName_.c_str(), "wrong edge opt type.\n");
            exit(EXIT_FAILURE);
        }
    }
}

/**
 * @brief Destroy the Edge Var object
 * 
 */
EdgeVar::~EdgeVar() {
    switch (optType_) {
        case UPLOAD_OPT: {
            this->DestroyUploadBuffer();
            break;
        }
        case DOWNLOAD_OPT: {
            this->DestroyRestoreBuffer();
            break;
        }
    }
}

/**
 * @brief init the upload buffer
 * 
 */
void EdgeVar::InitUploadBuffer() {
    // assign a random id to the container
    tool::CreateUUID(_curContainer.containerID, CONTAINER_ID_LENGTH);
    _curContainer.currentSize = 0;

    // for querying outside index 
    _outQuery.outQueryBase = (OutQueryEntry_t*) malloc(sizeof(OutQueryEntry_t) * 
        sendChunkBatchSize_);
    _outQuery.queryNum = 0;

    // init the recv buffer of chunks
    _recvChunkBuf.sendBuffer = (uint8_t*) malloc(sizeof(NetworkHead_t) + 
        sendChunkBatchSize_ * sizeof(Chunk_t));
    _recvChunkBuf.header = (NetworkHead_t*) _recvChunkBuf.sendBuffer;
    _recvChunkBuf.header->clientID = _edgeID;
    _recvChunkBuf.header->dataSize = 0;
    _recvChunkBuf.dataBuffer = _recvChunkBuf.sendBuffer + sizeof(NetworkHead_t);

    // init the recv buffer of fps
    _recvFpBuf.sendBuffer = (uint8_t*) malloc(sizeof(NetworkHead_t) + 
        sendRecipeBatchSize_ * sizeof(Chunk_t));
    _recvFpBuf.header = (NetworkHead_t*) _recvFpBuf.sendBuffer;
    _recvFpBuf.header->clientID = _edgeID;
    _recvFpBuf.header->dataSize = 0;
    _recvFpBuf.dataBuffer = _recvFpBuf.sendBuffer + sizeof(NetworkHead_t);

    // init the send buffer of fp bool array
    _sendFpBoolBuf.sendBuffer = (uint8_t*) malloc(sizeof(NetworkHead_t) + 
        sendRecipeBatchSize_ * sizeof(bool));
    _sendFpBoolBuf.header = (NetworkHead_t*) _sendFpBoolBuf.sendBuffer;
    _sendFpBoolBuf.header->clientID = _edgeID;
    _sendFpBoolBuf.header->dataSize = 0;
    _sendFpBoolBuf.dataBuffer = _sendFpBoolBuf.sendBuffer + sizeof(NetworkHead_t);

    // prepare the input MQ
#if (MULTI_CLIENT == 1)
    _inputMQ = new MessageQueue<Container_t>(1);
#else
    _inputMQ = new MessageQueue<Container_t>(CONTAINER_QUEUE_SIZE);
#endif
    // prepare the ciphertext recipe buffer
    _outRecipe.entryList = (uint8_t*) malloc(sendRecipeBatchSize_ * 
        CHUNK_HASH_SIZE);
    _outRecipe.recipeNum = 0;

    _outUpRecipe.entryList = (uint8_t*) malloc(sendRecipeBatchSize_ * 
        CHUNK_HASH_SIZE);
    _outUpRecipe.recipeNum = 0;

    // build the param passed to the enclave
    _upOutSGX.curContainer = &_curContainer;
    _upOutSGX.outRecipe = &_outRecipe;
    _upOutSGX.outUpRecipe = &_outUpRecipe;
    _upOutSGX.outQuery = &_outQuery;
    _upOutSGX.outClient = this;

    // init the file recipe
    _recipeWriteHandler.open(recipePath_, ios_base::trunc | ios_base::binary);
    if (!_recipeWriteHandler.is_open()) {
        tool::Logging(myName_.c_str(), "cannot init recipe file: %s\n",
            recipePath_.c_str());
        exit(EXIT_FAILURE);
    }
    FileRecipeHead_t virtualRecipeEnd;
    uint8_t isInEdge = IN_EDGE;
    _recipeWriteHandler.write((char*)&virtualRecipeEnd, sizeof(FileRecipeHead_t));
    _recipeWriteHandler.write((char*)&isInEdge, sizeof(uint8_t));

    // init the file upRecipe
    _upRecipeWriteHandler.open(upRecipePath_, ios_base::trunc | ios_base::binary);
    if (!_upRecipeWriteHandler.is_open()) {
        tool::Logging(myName_.c_str(), "cannot init upRecipe file: %s\n",
            recipePath_.c_str());
        exit(EXIT_FAILURE);
    }
    _recipeWriteHandler.write((char*)&virtualRecipeEnd, sizeof(FileRecipeHead_t));

    return ;
}

/**
 * @brief destroy the upload buffer
 * 
 */
void EdgeVar::DestroyUploadBuffer() {
    if (_recipeWriteHandler.is_open()) {
        _recipeWriteHandler.close();
    }
    free(_outRecipe.entryList);
    free(_outQuery.outQueryBase);
    free(_recvChunkBuf.sendBuffer);
    free(_recvFpBuf.sendBuffer);
    free(_sendFpBoolBuf.sendBuffer);
    delete _inputMQ;
    return ;
}

/**
 * @brief init the restore buffer
 * 
 */
void EdgeVar::InitRestoreBuffer() {
    // init buffer    
    _readRecipeBuf = (uint8_t*) malloc(sendRecipeBatchSize_ * CHUNK_HASH_SIZE);
    _reqContainer.idBuffer = (uint8_t*) malloc(CONTAINER_CAPPING_VALUE * 
        CONTAINER_ID_LENGTH);
    _reqContainer.containerArray = (uint8_t**) malloc(CONTAINER_CAPPING_VALUE * 
        sizeof(uint8_t*));
    _reqContainer.idNum = 0;
    _outRestoreEntry = (OutRestoreEntry_t*) malloc(sizeof(OutRestoreEntry_t) * sendRecipeBatchSize_);
    for (size_t i = 0; i < CONTAINER_CAPPING_VALUE; i++) {
        _reqContainer.containerArray[i] = (uint8_t*) malloc(sizeof(uint8_t) * 
            MAX_CONTAINER_SIZE);
    }
    recipeNum = 0;

    // init the send buffer
    _sendChunkBuf.sendBuffer = (uint8_t*) malloc(sizeof(NetworkHead_t) + 
        sendChunkBatchSize_ * sizeof(Chunk_t));
    _sendChunkBuf.header = (NetworkHead_t*) _sendChunkBuf.sendBuffer;
    _sendChunkBuf.header->clientID = _edgeID;
    _sendChunkBuf.header->dataSize = 0;
    _sendChunkBuf.dataBuffer = _sendChunkBuf.sendBuffer + sizeof(NetworkHead_t);

    // init the container cache
    _containerCache = new ReadCache();

    // build the param passed to the enclave
    _resOutSGX.reqContainer = &_reqContainer;
    _resOutSGX.sendChunkBuf = &_sendChunkBuf;
    _resOutSGX.outRestoreEntry = _outRestoreEntry;
    _resOutSGX.recipeNum = &recipeNum;
    _resOutSGX.outClient = this;

    // init the recipe handler
    _recipeReadHandler.open(recipePath_, ios_base::in | ios_base::binary);
    if (!_recipeReadHandler.is_open()) {
        tool::Logging(myName_.c_str(), "cannot init the file recipe: %s.\n",
            recipePath_.c_str());
        exit(EXIT_FAILURE);
    }
    return ;
}

/**
 * @brief destroy the restore buffer
 * 
 */
void EdgeVar::DestroyRestoreBuffer() {
    if (_recipeReadHandler.is_open()) {
        _recipeReadHandler.close();
    }
    free(_sendChunkBuf.sendBuffer);
    free(_readRecipeBuf);
    free(_reqContainer.idBuffer);
    for (size_t i = 0; i < CONTAINER_CAPPING_VALUE; i++) {
        free(_reqContainer.containerArray[i]);
    }
    free(_reqContainer.containerArray);
    delete _containerCache;
    return ;
}