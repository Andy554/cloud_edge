/**
 * @file ecallRecvDecoder.cc
 * @author Zuoru YANG (zryang@cse.cuhk.edu.hk)
 * @brief implement the interface of enclave-based recv decoder
 * @version 0.1
 * @date 2021-03-02
 * 
 * @copyright Copyright (c) 2021
 * 
 */

#include "../../include/ecallRecvDecoder.h"

/**
 * @brief Construct a new EcallRecvDecoder object
 * 
 */
EcallRecvDecoder::EcallRecvDecoder() {
    cryptoObj_ = new EcallCrypto(CIPHER_TYPE, HASH_TYPE);
    Enclave::Logging(myName_.c_str(), "init the RecvDecoder.\n");
}

/**
 * @brief Destroy the Ecall Recv Decoder object
 * 
 */
EcallRecvDecoder::~EcallRecvDecoder() {
    Enclave::Logging(myName_.c_str(), "========EcallFreqIndex Info-Restore========\n");
    Enclave::Logging(myName_.c_str(), "total restore_time: %lu\n", _restoretime);
    Enclave::Logging(myName_.c_str(), "total delta restore_time: %lu\n", _deltarestoretime);
    Enclave::Logging(myName_.c_str(), "===================================\n");
    delete(cryptoObj_);
}

/**
 * @brief process a batch of recipes and write chunk to the outside buffer
 * 
 * @param recipeBuffer the pointer to the recipe buffer
 * @param recipeNum the input recipe buffer
 * @param resOutSGX the pointer to the out-enclave var
 * 
 * @return size_t the size of the sended buffer
 */
void EcallRecvDecoder::ProcRecipeBatch(uint8_t* recipeBuffer, size_t recipeNum, 
    ResOutSGX_t* resOutSGX) {
    Enclave::Logging(myName_.c_str(), "start to restore a batch.\n");

    Ocall_GetCurrentTime(&_starttime);
    // out-enclave info
    ReqContainer_t* reqContainer = (ReqContainer_t*)resOutSGX->reqContainer;
    uint8_t* idBuffer = reqContainer->idBuffer;
    uint8_t** containerArray = reqContainer->containerArray;
    SendMsgBuffer_t* sendChunkBuf = resOutSGX->sendChunkBuf;

    // in-enclave info
    EnclaveClient* sgxClient = (EnclaveClient*)resOutSGX->sgxClient;
    SendMsgBuffer_t* restoreChunkBuf = &sgxClient->_restoreChunkBuffer;
    EVP_CIPHER_CTX* cipherCtx = sgxClient->_cipherCtx;
    uint8_t* sessionKey = sgxClient->_sessionKey;
    uint8_t* masterKey = sgxClient->_masterKey;

    string tmpContainerNameStr;
    unordered_map<string, uint32_t> tmpContainerMap;
    tmpContainerMap.reserve(CONTAINER_CAPPING_VALUE);

    // 用于构建inRestoreEntry
    InRestoreEntry_t* inRestoreEntry = sgxClient->_inRestoreEntry;
    // 用于restore chunk时读取entry
    InRestoreEntry_t* inRestoreEntryForRestore = sgxClient->_inRestoreEntry;
    OutRestoreEntry_t* outRestoreEntry = resOutSGX->outRestoreEntry;
    uint8_t tmpHash[CHUNK_HASH_SIZE];

    // ------------------------------------
    // 构建restore时每个chunk的entry
    // ------------------------------------

    // decrypt the recipe file
    // 把FP读取到recipe buffer里面
    cryptoObj_->DecryptWithKey(cipherCtx, recipeBuffer, recipeNum * CHUNK_HASH_SIZE,
        masterKey, sgxClient->_plainHashBuffer);
    // 复制recipeNum
    *resOutSGX->recipeNum = recipeNum;
    Enclave::Logging(myName_.c_str(), "Dec file recipe successful.\n");
    
    for(size_t i = 0; i < recipeNum; i++) {
        // 更新inRestoreEntry
        memcpy(inRestoreEntry->chunkHash, sgxClient->_plainHashBuffer + i * CHUNK_HASH_SIZE, 
            CHUNK_HASH_SIZE);
        // 直接把FP当做MLE Key
        memcpy(inRestoreEntry->mleKey, sgxClient->_plainHashBuffer + i * CHUNK_HASH_SIZE, 
            CHUNK_HASH_SIZE);
        inRestoreEntry++;

        // 更新outRestoreEntry
        // 提取一个FP，然后加密
        memcpy(tmpHash, sgxClient->_plainHashBuffer, CHUNK_HASH_SIZE);
        cryptoObj_->IndexAESCMCEnc(cipherCtx, tmpHash, CHUNK_HASH_SIZE,
            Enclave::indexQueryKey_, tmpHash);
        // 传输到outClient
        memcpy(outRestoreEntry->chunkHash, tmpHash, CHUNK_HASH_SIZE);
        outRestoreEntry++;

        // if(!i) {
        //     Enclave::Logging(myName_.c_str(), "Enc Chunk Hash:%s\n", tmpHash);
        //     for(size_t i = 0; i < 32; i++) {
        //         Enclave::Logging(myName_.c_str(), "%d\n", (uint32_t)tmpHash[i]);
        //     }
        // }
    }
    Enclave::Logging(myName_.c_str(), "generate restore entry success.\n");

    // ------------------------------------
    // 查询index，通过FP获取容器的位置
    // ------------------------------------
    
    // query FP index
    Ocall_QueryOutIndexForRestore(resOutSGX->outClient);
    Enclave::Logging(myName_.c_str(), "query successful.\n");
    
    // ------------------------------------
    // 逐个恢复chunk
    // ------------------------------------

    outRestoreEntry = resOutSGX->outRestoreEntry;
    inRestoreEntry = sgxClient->_inRestoreEntry;
    for (size_t i = 0, j = 0; i < recipeNum; i++) {

        // ------------------------------------
        // 获取container name
        // ------------------------------------

        // Enclave::Logging(myName_.c_str(), "restoring...: %lu\n", i);

        // 解密containerName
        cryptoObj_->DecryptWithKey(cipherCtx, outRestoreEntry->edgeContainerName,
                            CONTAINER_ID_LENGTH, sgxClient->_masterKey, 
                            inRestoreEntry->edgeContainerName);

        // Enclave::Logging(myName_.c_str(), "restore edge container name: %s\n", 
        //     inRestoreEntry->edgeContainerName);

        tmpContainerNameStr.assign((char*)inRestoreEntry->edgeContainerName, CONTAINER_ID_LENGTH);
        auto findResult = tmpContainerMap.find(tmpContainerNameStr);

        if (findResult == tmpContainerMap.end()) {
            // 实现ID到ID号的映射
            tmpContainerMap[tmpContainerNameStr] = reqContainer->idNum;
            // 更新到reqContainer
            memcpy(idBuffer + reqContainer->idNum * CONTAINER_ID_LENGTH, 
                tmpContainerNameStr.c_str(), CONTAINER_ID_LENGTH);
            // 更新ContainerID到inEntry
            inRestoreEntry->containerID = reqContainer->idNum;

            reqContainer->idNum++;
        }
        else {
             inRestoreEntry->containerID = findResult->second;
        }

        // ------------------------------------
        // 当所需container的数量达到container buffer的上线，
        // 开始读取container并恢复这部分chunk
        // ------------------------------------

        if (reqContainer->idNum == CONTAINER_CAPPING_VALUE || i == recipeNum - 1) {
            // 加载容器
            Ocall_GetReqContainers(resOutSGX->outClient);
            
            // 对已经加载container的chunk进行恢复
            for(j; j <= i; j++) {
                uint32_t containerID = inRestoreEntryForRestore->containerID;
                uint8_t* chunkBuffer = containerArray[containerID];

                // if(j == 0) {
                //     this->RecoverOneChunk(chunkBuffer, inRestoreEntryForRestore->mleKey, 
                //         inRestoreEntryForRestore->chunkHash, restoreChunkBuf, cipherCtx);
                // }
                this->RecoverOneChunk(chunkBuffer, inRestoreEntryForRestore->mleKey, 
                    inRestoreEntryForRestore->chunkHash, restoreChunkBuf, cipherCtx);

                // ------------------------------------
                // 当恢复的chunk数量到达一个batch大小时，开始向client发送data
                // ------------------------------------

                if (restoreChunkBuf->header->currentItemNum % 
                    Enclave::sendChunkBatchSize_ == 0 || j == i) {
                    cryptoObj_->SessionKeyEnc(cipherCtx, restoreChunkBuf->dataBuffer,
                        restoreChunkBuf->header->dataSize, sessionKey, sendChunkBuf->dataBuffer);
                    
                    // copy the header to the send buffer
                    restoreChunkBuf->header->messageType = SERVER_RESTORE_CHUNK;
                    memcpy(sendChunkBuf->header, restoreChunkBuf->header, sizeof(NetworkHead_t));
                    Ocall_SendRestoreData(resOutSGX->outClient);

                    restoreChunkBuf->header->dataSize = 0;
                    restoreChunkBuf->header->currentItemNum = 0;
                }
                
                inRestoreEntryForRestore++;
            }

            reqContainer->idNum = 0;
            tmpContainerMap.clear();
        }

        outRestoreEntry++;
        inRestoreEntry++;
    }

    return ;

// ------------------------------------
// START for origin
// ------------------------------------

    // RecipeEntry_t* tmpRecipeEntry;
    // tmpRecipeEntry = (RecipeEntry_t*)sgxClient->_plainRecipeBuffer;

    // for (size_t i = 0; i < recipeNum; i++) {
    //     // parse the recipe entry one-by-one
    //     tmpContainerIDStr.assign((char*)tmpRecipeEntry->edgeContainerName, CONTAINER_ID_LENGTH);
    //     memcpy(tmpEnclaveRecipeEntry->chunkHash, tmpRecipeEntry);
    //     tmpEnclaveRecipeEntry.offset = tmpRecipeEntry->offset;
    //     tmpEnclaveRecipeEntry.length = tmpRecipeEntry->length;

    //     auto findResult = tmpContainerMap.find(tmpContainerIDStr);
    //     if (findResult == tmpContainerMap.end()) {
    //         // this is a unique container entry, it does not exist in current local index
    //         tmpEnclaveRecipeEntry.containerID = reqContainer->idNum;
    //         tmpContainerMap[tmpContainerIDStr] = reqContainer->idNum;
    //         memcpy(idBuffer + reqContainer->idNum * CONTAINER_ID_LENGTH, 
    //             tmpContainerIDStr.c_str(), CONTAINER_ID_LENGTH);
    //         reqContainer->idNum++;
    //     } else {
    //         // this is a duplicate container entry, using existing result.
    //         tmpEnclaveRecipeEntry.containerID = findResult->second;
    //     }
    //    sgxClient->_enclaveRecipeBuffer.push_back(tmpEnclaveRecipeEntry);

    //     // judge whether reach the capping value 
    //     if (reqContainer->idNum == CONTAINER_CAPPING_VALUE) {
    //         // start to let outside application to fetch the container data
    //         Ocall_GetReqContainers(resOutSGX->outClient);

    //         // read chunk from the encrypted container buffer, 
    //         // write the chunk to the outside buffer
    //         for (size_t idx = 0; idx < sgxClient->_enclaveRecipeBuffer.size(); idx++) {
    //             uint32_t containerID = sgxClient->_enclaveRecipeBuffer[idx].containerID;
    //             uint32_t offset = sgxClient->_enclaveRecipeBuffer[idx].offset;
    //             uint32_t chunkSize = sgxClient->_enclaveRecipeBuffer[idx].length;
    //             uint8_t* chunkBuffer = containerArray[containerID] + offset;
    //             this->RecoverOneChunk(chunkBuffer, chunkSize, restoreChunkBuf, cipherCtx);
    //             if (restoreChunkBuf->header->currentItemNum % 
    //                 Enclave::sendChunkBatchSize_ == 0) {
    //                 cryptoObj_->SessionKeyEnc(cipherCtx, restoreChunkBuf->dataBuffer,
    //                     restoreChunkBuf->header->dataSize, sessionKey, sendChunkBuf->dataBuffer);
                    
    //                 // copy the header to the send buffer
    //                 restoreChunkBuf->header->messageType = SERVER_RESTORE_CHUNK;
    //                 memcpy(sendChunkBuf->header, restoreChunkBuf->header, sizeof(NetworkHead_t));
    //                 Ocall_SendRestoreData(resOutSGX->outClient);

    //                 restoreChunkBuf->header->dataSize = 0;
    //                 restoreChunkBuf->header->currentItemNum = 0;
    //             }
    //         }

    //         // reset 
            // reqContainer->idNum = 0;
            // tmpContainerMap.clear();
    //         sgxClient->_enclaveRecipeBuffer.clear();
    //     }
    //     tmpRecipeEntry++;
    // }
    // Ocall_GetCurrentTime(&_endtime);
    // _restoretime += _endtime - _starttime;

    // return ;

// ------------------------------------
// END for origin
// ------------------------------------
}

void EcallRecvDecoder::ProcRecipeBatchForEdgeUpload(uint8_t* recipeBuffer, size_t recipeNum, 
    ResOutSGX_t* resOutSGX, bool* isIncloud) {

    Ocall_GetCurrentTime(&_starttime);
    // out-enclave info
    ReqContainer_t* reqContainer = (ReqContainer_t*)resOutSGX->reqContainer;
    uint8_t* idBuffer = reqContainer->idBuffer;
    uint8_t** containerArray = reqContainer->containerArray;
    SendMsgBuffer_t* sendChunkBuf = resOutSGX->sendChunkBuf;

    // in-enclave info
    EnclaveClient* sgxClient = (EnclaveClient*)resOutSGX->sgxClient;
    SendMsgBuffer_t* restoreChunkBuf = &sgxClient->_restoreChunkBuffer;
    EVP_CIPHER_CTX* cipherCtx = sgxClient->_cipherCtx;
    uint8_t* masterKey = sgxClient->_masterKey;

    string tmpContainerNameStr;
    unordered_map<string, uint32_t> tmpContainerMap;
    tmpContainerMap.reserve(CONTAINER_CAPPING_VALUE);

    // 用于构建inRestoreEntry
    InRestoreEntry_t* inRestoreEntry = sgxClient->_inRestoreEntry;
    // 用于restore chunk时读取entry
    InRestoreEntry_t* inRestoreEntryForRestore = sgxClient->_inRestoreEntry;
    OutRestoreEntry_t* outRestoreEntry = resOutSGX->outRestoreEntry;
    uint8_t tmpHash[CHUNK_HASH_SIZE];

    // ------------------------------------
    // 构建restore时每个chunk的entry
    // ------------------------------------

    // decrypt the recipe file
    // 把FP读取到recipe buffer里面
    cryptoObj_->DecryptWithKey(cipherCtx, recipeBuffer, recipeNum * CHUNK_HASH_SIZE,
        masterKey, sgxClient->_plainHashBuffer);
    Enclave::Logging(myName_.c_str(), "Dec file recipe successful.\n");
    
    uint8_t upChunkNum = 0;
    for(size_t i = 0; i < recipeNum; i++) {
        if(!isIncloud[i]){
            // 更新inRestoreEntry
            memcpy(inRestoreEntry->chunkHash, sgxClient->_plainHashBuffer + i * CHUNK_HASH_SIZE, 
                CHUNK_HASH_SIZE);

            // 更新outRestoreEntry
            // 提取一个FP，然后加密
            memcpy(tmpHash, sgxClient->_plainHashBuffer, CHUNK_HASH_SIZE);
            cryptoObj_->IndexAESCMCEnc(cipherCtx, tmpHash, CHUNK_HASH_SIZE,
                Enclave::indexQueryKey_, tmpHash);
            // 传输到outClient
            memcpy(outRestoreEntry->chunkHash, tmpHash, CHUNK_HASH_SIZE);
            upChunkNum++;
        }
        inRestoreEntry++;
        outRestoreEntry++;
    }
    *resOutSGX->recipeNum = upChunkNum;

    // ------------------------------------
    // 查询index，通过FP获取容器的位置
    // ------------------------------------
    
    // query FP index
    Ocall_QueryOutIndexForRestore(resOutSGX->outClient);
    Enclave::Logging(myName_.c_str(), "query successful.\n");
    
    // ------------------------------------
    // 逐个恢复chunk
    // ------------------------------------

    outRestoreEntry = resOutSGX->outRestoreEntry;
    inRestoreEntry = sgxClient->_inRestoreEntry;
    for (size_t i = 0, j = 0; i < upChunkNum; i++) {

        // ------------------------------------
        // 获取container name
        // ------------------------------------

        // Enclave::Logging(myName_.c_str(), "restoring...: %lu\n", i);

        // 解密containerName
        cryptoObj_->DecryptWithKey(cipherCtx, outRestoreEntry->edgeContainerName,
                            CONTAINER_ID_LENGTH, sgxClient->_masterKey, 
                            inRestoreEntry->edgeContainerName);

        // Enclave::Logging(myName_.c_str(), "restore edge container name: %s\n", 
        //     inRestoreEntry->edgeContainerName);

        tmpContainerNameStr.assign((char*)inRestoreEntry->edgeContainerName, CONTAINER_ID_LENGTH);
        auto findResult = tmpContainerMap.find(tmpContainerNameStr);

        if (findResult == tmpContainerMap.end()) {
            // 实现ID到ID号的映射
            tmpContainerMap[tmpContainerNameStr] = reqContainer->idNum;
            // 更新到reqContainer
            memcpy(idBuffer + reqContainer->idNum * CONTAINER_ID_LENGTH, 
                tmpContainerNameStr.c_str(), CONTAINER_ID_LENGTH);
            // 更新ContainerID到inEntry
            inRestoreEntry->containerID = reqContainer->idNum;

            reqContainer->idNum++;
        }
        else {
             inRestoreEntry->containerID = findResult->second;
        }

        // ------------------------------------
        // 当所需container的数量达到container buffer的上线，
        // 开始读取container并恢复这部分chunk
        // ------------------------------------

        if (reqContainer->idNum == CONTAINER_CAPPING_VALUE || i == upChunkNum - 1) {
            // 加载容器
            Ocall_GetReqContainers(resOutSGX->outClient);
            
            // 对已经加载container的chunk进行恢复
            for(j; j <= i; j++) {
                uint32_t containerID = inRestoreEntryForRestore->containerID;
                uint8_t* chunkBuffer = containerArray[containerID];

                // if(j == 0) {
                //     this->RecoverOneChunk(chunkBuffer, inRestoreEntryForRestore->mleKey, 
                //         inRestoreEntryForRestore->chunkHash, restoreChunkBuf, cipherCtx);
                // }
                this->RecoverOneChunkForEdgeUpload(chunkBuffer, inRestoreEntryForRestore->chunkHash, 
                    restoreChunkBuf);

                // ------------------------------------
                // 当恢复的chunk数量到达一个batch大小时，开始向client发送data
                // ------------------------------------

                if (restoreChunkBuf->header->currentItemNum % 
                    Enclave::sendChunkBatchSize_ == 0 || j == i) {
                    
                    // copy the header to the send buffer
                    restoreChunkBuf->header->messageType = EDGE_UPLOAD_CHUNK;
                    memcpy(sendChunkBuf->header, restoreChunkBuf->header, sizeof(NetworkHead_t));
                    Ocall_SendRestoreData(resOutSGX->outClient);

                    restoreChunkBuf->header->dataSize = 0;
                    restoreChunkBuf->header->currentItemNum = 0;
                }
                
                inRestoreEntryForRestore++;
            }

            reqContainer->idNum = 0;
            tmpContainerMap.clear();
        }

        outRestoreEntry++;
        inRestoreEntry++;
    }

    return ;
}

/**
 * @brief process the tail batch of recipes
 * 
 * @param resOutSGX the pointer to the out-enclave var
 */
void EcallRecvDecoder::ProcRecipeTailBatch(ResOutSGX_t* resOutSGX) {

    // out-enclave info
    SendMsgBuffer_t* sendChunkBuf = resOutSGX->sendChunkBuf;

    // in-enclave info
    EnclaveClient* sgxClient = (EnclaveClient*)resOutSGX->sgxClient;
    EVP_CIPHER_CTX* cipherCtx = sgxClient->_cipherCtx;
    uint8_t* sessionKey = sgxClient->_sessionKey;
    SendMsgBuffer_t* restoreChunkBuf = &sgxClient->_restoreChunkBuffer;

    // ------------------------------------
    // 发送消息提示client chunk恢复完毕
    // ------------------------------------

    cryptoObj_->SessionKeyEnc(cipherCtx, restoreChunkBuf->dataBuffer,
        restoreChunkBuf->header->dataSize, sessionKey,
        sendChunkBuf->dataBuffer);

    // copy the header to the send buffer
    restoreChunkBuf->header->messageType = SERVER_RESTORE_FINAL;
    memcpy(sendChunkBuf->header, restoreChunkBuf->header, sizeof(NetworkHead_t));
    Ocall_SendRestoreData(resOutSGX->outClient);

    restoreChunkBuf->header->currentItemNum = 0;
    restoreChunkBuf->header->dataSize = 0;

    return ;
    
}

void EcallRecvDecoder::ProcRecipeTailBatchForEdgeUpload(ResOutSGX_t* resOutSGX) {

    // out-enclave info
    SendMsgBuffer_t* sendChunkBuf = resOutSGX->sendChunkBuf;

    // in-enclave info
    EnclaveClient* sgxClient = (EnclaveClient*)resOutSGX->sgxClient;
    SendMsgBuffer_t* restoreChunkBuf = &sgxClient->_restoreChunkBuffer;

    // ------------------------------------
    // 发送消息提示cloud chunk上传完毕
    // ------------------------------------

    // copy the header to the send buffer
    restoreChunkBuf->header->messageType = EDGE_UPLOAD_CHUNK_END;
    memcpy(sendChunkBuf->header, restoreChunkBuf->header, sizeof(NetworkHead_t));
    Ocall_SendRestoreData(resOutSGX->outClient);

    restoreChunkBuf->header->currentItemNum = 0;
    restoreChunkBuf->header->dataSize = 0;

    return ;
    
}

/**
 * @brief recover a chunk
 * 
 * @param chunkBuffer the chunk buffer
 * @param chunkSize the chunk size
 * @param restoreChunkBuf the restore chunk buffer
 * @param cipherCtx the pointer to the EVP cipher
 * 
 */
void EcallRecvDecoder::RecoverOneChunk(uint8_t* chunkBuffer, uint8_t* MLEKey,
        uint8_t* chunkHash, SendMsgBuffer_t* restoreChunkBuf, EVP_CIPHER_CTX* cipherCtx) {
    uint8_t* outputBuffer = restoreChunkBuf->dataBuffer + 
        restoreChunkBuf->header->dataSize;
    uint8_t decompressedChunk[MAX_CHUNK_SIZE];

    string tmpChunkHashORI;
    string tmpChunkHashGET;
    size_t bufferOffset;
    size_t chunkLength;
    size_t chunkOffset;
    size_t chunkNum = 0;
    
    // --------------------
    // 获取chunk在container中的位置
    // --------------------

    // 获取这个container chunk的数量
    chunkNum = (chunkBuffer[0] << 0) +
                (chunkBuffer[1] << 8) +
                (chunkBuffer[2] << 16) +
                (chunkBuffer[3] << 24);
    // Enclave::Logging(myName_.c_str(), "recover one chunk: restore chunk num: %lu\n", chunkNum);

    // 获取chunk的FP以及长度和偏移
    bufferOffset = 4u;
    chunkLength = 0u;
    chunkOffset = 0u;
    tmpChunkHashORI.assign((char*)chunkHash, CHUNK_HASH_SIZE);

    // Enclave::Logging(myName_.c_str(), "recover one chunk: ori chunk Hash: %s.\n", tmpChunkHashORI.c_str());
    // uint8_t tmpchar[CHUNK_HASH_SIZE];
    // for (size_t i = 0; i < 32; i++) {
        // tmpchar[i] = chunkBuffer[i+3];
        // Enclave::Logging(myName_.c_str(), "ori hash: %d\n", (int)chunkHash[i]);
        // Enclave::Logging(myName_.c_str(), "get hash: %d\n", (int)chunkBuffer[i+3]);
    // }
    // for (size_t i = 0; i < 32; i++) {
        // tmpchar[i] = chunkBuffer[i+3];
        // Enclave::Logging(myName_.c_str(), "ori hash: %d\n", (int)chunkHash[i]);
        // Enclave::Logging(myName_.c_str(), "get hash: %d\n", (int)chunkBuffer[i+4]);
    // }
    // Enclave::Logging(myName_.c_str(), "recover one chunk: get chunk Hash: %s\n", tmpchar);

    for (size_t i = 0; i < chunkNum; i++){
        // 获取一个hash
        tmpChunkHashGET.resize(CHUNK_HASH_SIZE, 0);
        tmpChunkHashGET.assign((char*)chunkBuffer + bufferOffset, CHUNK_HASH_SIZE);
        // Enclave::Logging(myName_.c_str(), "recover one chunk: get chunk Hash: %s.\n", tmpChunkHashGET.c_str());
        if (!tmpChunkHashORI.compare(tmpChunkHashGET)) {
            // Enclave::Logging(myName_.c_str(), "find success.\n");

            bufferOffset += CHUNK_HASH_SIZE;
            // 找到hash 读取长度和偏移
            chunkOffset = (chunkBuffer[bufferOffset + 0u] << 0) +
                            (chunkBuffer[bufferOffset + 1u] << 8) +
                            (chunkBuffer[bufferOffset + 2u] << 16) +
                            (chunkBuffer[bufferOffset + 3u] << 24);
            chunkOffset += (CHUNK_HASH_SIZE + 8u) * chunkNum + 4u;

            bufferOffset += 4u;
            chunkLength = (chunkBuffer[bufferOffset + 0u] << 0) +
                            (chunkBuffer[bufferOffset + 1u] << 8) +
                            (chunkBuffer[bufferOffset + 2u] << 16) +
                            (chunkBuffer[bufferOffset + 3u] << 24);
            break;
        }
        bufferOffset += CHUNK_HASH_SIZE + 8u;
    }

    // --------------------
    // 获取chunk并依据MLE key解密
    // --------------------
    
    cryptoObj_->DecryptWithKey(cipherCtx, chunkBuffer + chunkOffset, chunkLength,
        MLEKey, decompressedChunk);

    // --------------------
    // 解压chunk，并添加至out buffer
    // --------------------

    // try to decompress the chunk
    int decompressedSize = LZ4_decompress_safe((char*)decompressedChunk, 
        (char*)(outputBuffer + sizeof(uint32_t)), chunkLength, MAX_CHUNK_SIZE);
    if (decompressedSize > 0) {
        // it can do the decompression, write back the decompressed chunk size
        memcpy(outputBuffer, &decompressedSize, sizeof(uint32_t));
        restoreChunkBuf->header->dataSize += sizeof(uint32_t) + decompressedSize; 
    } else {
        // it cannot do the decompression
        memcpy(outputBuffer, &chunkLength, sizeof(uint32_t));
        memcpy(outputBuffer + sizeof(uint32_t), decompressedChunk, chunkLength);
        restoreChunkBuf->header->dataSize += sizeof(uint32_t) + chunkLength;
    }

    restoreChunkBuf->header->currentItemNum++;
    return ;

    // ------------------------------------
    // START for origin
    // ------------------------------------

    // // first decrypt the chunk first
    // cryptoObj_->DecryptionWithKeyIV(cipherCtx, chunkBuffer, chunkSize, 
    //     Enclave::enclaveKey_, decompressedChunk, iv);

    // // try to decompress the chunk
    // int decompressedSize = LZ4_decompress_safe((char*)decompressedChunk, 
    //     (char*)(outputBuffer + sizeof(uint32_t)), chunkSize, MAX_CHUNK_SIZE);
    // if (decompressedSize > 0) {
    //     // it can do the decompression, write back the decompressed chunk size
    //     memcpy(outputBuffer, &decompressedSize, sizeof(uint32_t));
    //     restoreChunkBuf->header->dataSize += sizeof(uint32_t) + decompressedSize; 
    // } else {
    //     // it cannot do the decompression
    //     memcpy(outputBuffer, &chunkSize, sizeof(uint32_t));
    //     memcpy(outputBuffer + sizeof(uint32_t), decompressedChunk, chunkSize);
    //     restoreChunkBuf->header->dataSize += sizeof(uint32_t) + chunkSize;
    // }

    // restoreChunkBuf->header->currentItemNum++;
    // return ;

    // ------------------------------------
    // END for origin
    // ------------------------------------
}

void EcallRecvDecoder::RecoverOneChunkForEdgeUpload(uint8_t* chunkBuffer, 
        uint8_t* chunkHash, SendMsgBuffer_t* restoreChunkBuf) {
    uint8_t* outputBuffer = restoreChunkBuf->dataBuffer + 
        restoreChunkBuf->header->dataSize;

    string tmpChunkHashORI;
    string tmpChunkHashGET;
    size_t bufferOffset;
    size_t chunkLength;
    size_t chunkOffset;
    size_t chunkNum = 0;
    
    // --------------------
    // 获取chunk在container中的位置
    // --------------------

    // 获取这个container chunk的数量
    chunkNum = (chunkBuffer[0] << 0) +
                (chunkBuffer[1] << 8) +
                (chunkBuffer[2] << 16) +
                (chunkBuffer[3] << 24);
    // Enclave::Logging(myName_.c_str(), "recover one chunk: restore chunk num: %lu\n", chunkNum);

    // 获取chunk的FP以及长度和偏移
    bufferOffset = 4u;
    chunkLength = 0u;
    chunkOffset = 0u;
    tmpChunkHashORI.assign((char*)chunkHash, CHUNK_HASH_SIZE);


    for (size_t i = 0; i < chunkNum; i++){
        // 获取一个hash
        tmpChunkHashGET.resize(CHUNK_HASH_SIZE, 0);
        tmpChunkHashGET.assign((char*)chunkBuffer + bufferOffset, CHUNK_HASH_SIZE);
        // Enclave::Logging(myName_.c_str(), "recover one chunk: get chunk Hash: %s.\n", tmpChunkHashGET.c_str());
        if (!tmpChunkHashORI.compare(tmpChunkHashGET)) {
            // Enclave::Logging(myName_.c_str(), "find success.\n");

            bufferOffset += CHUNK_HASH_SIZE;
            // 找到hash 读取长度和偏移
            chunkOffset = (chunkBuffer[bufferOffset + 0u] << 0) +
                            (chunkBuffer[bufferOffset + 1u] << 8) +
                            (chunkBuffer[bufferOffset + 2u] << 16) +
                            (chunkBuffer[bufferOffset + 3u] << 24);
            chunkOffset += (CHUNK_HASH_SIZE + 8u) * chunkNum + 4u;

            bufferOffset += 4u;
            chunkLength = (chunkBuffer[bufferOffset + 0u] << 0) +
                            (chunkBuffer[bufferOffset + 1u] << 8) +
                            (chunkBuffer[bufferOffset + 2u] << 16) +
                            (chunkBuffer[bufferOffset + 3u] << 24);
            break;
        }
        bufferOffset += CHUNK_HASH_SIZE + 8u;
    }

    memcpy(outputBuffer, &chunkLength, sizeof(uint32_t));
    memcpy(outputBuffer + sizeof(uint32_t), chunkBuffer + chunkOffset, chunkLength);
    restoreChunkBuf->header->dataSize += sizeof(uint32_t) + chunkLength;

    restoreChunkBuf->header->currentItemNum++;
    return ;
}