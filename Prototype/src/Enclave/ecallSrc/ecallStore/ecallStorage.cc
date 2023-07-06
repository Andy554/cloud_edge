/**
 * @file ecallStorage.cc
 * @author Zuoru YANG (zryang@cse.cuhk.edu.hk)
 * @brief implement the interface of storage core inside the enclave 
 * @version 0.1
 * @date 2020-12-16
 * 
 * @copyright Copyright (c) 2020
 * 
 */

#include "../../include/ecallStorage.h"

/**
 * @brief Construct a new Ecall Storage Core object
 * 
 */
EcallStorageCore::EcallStorageCore() {
    Enclave::Logging(myName_.c_str(), "init the StorageCore.\n");
}

 /**
 * @brief Destroy the Ecall Storage Core object
 * 
 */
EcallStorageCore::~EcallStorageCore() {
    Enclave::Logging(myName_.c_str(), "========StorageCore Info========\n");
    Enclave::Logging(myName_.c_str(), "write the data size: %lu\n", writtenDataSize_);
    Enclave::Logging(myName_.c_str(), "write chunk num: %lu\n", writtenChunkNum_);
    Enclave::Logging(myName_.c_str(), "================================\n");
}

/**
 * @brief save the chunk to the storage serve
 * 
 * @param chunkData the chunk data buffer
 * @param chunkSize the chunk size
 * @param chunkAddr the chunk address (return)
 * @param sgxClient the current client
 * @param upOutSGX the pointer to outside SGX buffer
 */
void EcallStorageCore::SaveChunk(char* chunkData, uint32_t chunkSize,
    RecipeEntry_t* chunkAddr, UpOutSGX_t* upOutSGX) {
    // assign a chunk length
    EnclaveClient* sgxClient = (EnclaveClient*)upOutSGX->sgxClient;
    InContainer* inContainer = &sgxClient->_inContainer;
    Container_t* outContainer = upOutSGX->curContainer;

    chunkAddr->length = chunkSize;
    uint32_t saveOffset = inContainer->curSize;
    uint32_t writeOffset = saveOffset;

    if (CRYPTO_BLOCK_SIZE + chunkSize + saveOffset < MAX_CONTAINER_SIZE) {
        // current container can store this chunk
        // copy data to this container
        memcpy(inContainer->buf + writeOffset, chunkData, chunkSize);
        writeOffset += chunkSize;
        memcpy(inContainer->buf + writeOffset, sgxClient->_iv, CRYPTO_BLOCK_SIZE);
        memcpy(chunkAddr->containerName, outContainer->containerID, CONTAINER_ID_LENGTH);
    } else {
        // current container cannot store this chunk, write this container to the outside buffer
        // create a new container for this new chunk
        memcpy(outContainer->body, inContainer->buf, inContainer->curSize);
        outContainer->currentSize = inContainer->curSize;
        inContainer->curSize = 0;
        Ocall_WriteContainer(upOutSGX->outClient);
        // reset this container during the ocall

        saveOffset = 0;
        writeOffset = saveOffset;
        memcpy(inContainer->buf + writeOffset, chunkData, chunkSize);
        writeOffset += chunkSize;
        memcpy(inContainer->buf + writeOffset, sgxClient->_iv, CRYPTO_BLOCK_SIZE);
        memcpy(chunkAddr->containerName, outContainer->containerID, CONTAINER_ID_LENGTH);
    }

    inContainer->curSize += chunkSize;
    inContainer->curSize += CRYPTO_BLOCK_SIZE;

    chunkAddr->offset = saveOffset;

    writtenDataSize_ += chunkSize;
    writtenChunkNum_++;

    return ;
}

/**
* @brief save the chunk to the storage serve
* 
* @param chunkData the chunk data buffer
* @param chunkSize the chunk size
* @param edgeContainerName the container address
* @param upOutSGX the pointer to outside SGX buffer
* @param chunkHash the hash of the data chunk
*/
void EcallStorageCore::SaveChunkWithMLEKey(char* chunkData, uint32_t chunkSize,
        uint8_t* edgeContainerName, UpOutSGX_t* upOutSGX, string chunkHash){

    // char chartmphash[CHUNK_HASH_SIZE];
    // memcpy(chartmphash, chunkHash.c_str(), CHUNK_HASH_SIZE);
    // for(size_t i = 0; i < 32; i++) {
    //     Enclave::Logging(myName_.c_str(), "save chunk with mle key: chunk hash: %d.\n", (int)chartmphash[i]);
    // }

    // assign a chunk length
    EnclaveClient* sgxClient = (EnclaveClient*)upOutSGX->sgxClient;
    InContainer* inContainer = &sgxClient->_inContainer;
    Container_t* outContainer = upOutSGX->curContainer;

    // chunk data存的初始位置
    uint32_t saveOffset = inContainer->curSize;
    uint32_t writeOffset = saveOffset;
    // header存的初始位置
    uint32_t headerSaveOffset = inContainer->curHeaderSize;
    uint32_t headerWriteOffset = headerSaveOffset;

    // 转换offset和length变成char
    uint8_t charOffset[4];
    uint8_t charChunkSize[4];
    charOffset[0] = (saveOffset >> 0) & 255;
    charOffset[1] = (saveOffset >> 8) & 255;
    charOffset[2] = (saveOffset >> 16) & 255;
    charOffset[3] = (saveOffset >> 24) & 255;
    charChunkSize[0] = (chunkSize >> 0) & 255;
    charChunkSize[1] = (chunkSize >> 8) & 255;
    charChunkSize[2] = (chunkSize >> 16) & 255;
    charChunkSize[3] = (chunkSize >> 24) & 255;

    uint32_t maxSize = MAX_CONTAINER_SIZE - 4u;
    uint32_t storageSize = CHUNK_HASH_SIZE + 8u + chunkSize;
    uint32_t tmpTotal = storageSize + saveOffset + headerSaveOffset;

    if (tmpTotal < maxSize) {
        // current container can store this chunk
        // copy data to this container
        // 复制chunk数据到incontainer的buf
        //Enclave::Logging("DEBUG","update inContainer\n");
        memcpy(inContainer->buf + writeOffset, chunkData, chunkSize);
        // 复制FP到incontainer的headerbuf
        memcpy(inContainer->headerBuf + headerWriteOffset, chunkHash.c_str(), CHUNK_HASH_SIZE);
        headerWriteOffset += CHUNK_HASH_SIZE;
        // 复制chunk偏移和长度到headerbuf
        memcpy(inContainer->headerBuf + headerWriteOffset, charOffset, 4u);
        headerWriteOffset += 4u;
        memcpy(inContainer->headerBuf + headerWriteOffset, charChunkSize, 4u);

        // 复制container ID到entry
        memcpy(edgeContainerName, outContainer->containerID, CONTAINER_ID_LENGTH);

        inContainer->curSize += chunkSize;
        inContainer->curHeaderSize += CHUNK_HASH_SIZE;
        inContainer->curHeaderSize += 8u;
        inContainer->curNum = inContainer->curNum + 1;

        // for(size_t i = 0; i < 32; i++) {
        // Enclave::Logging(myName_.c_str(), "save chunk with mle key: header buf: %d.\n", (int)inContainer->headerBuf[i]);
        // }
    } else {
        // current container cannot store this chunk, write this container to the outside buffer
        // create a new container for this new chunk

        // 转换num到char
        uint8_t charChunkNum[4];
        charChunkNum[0] = (inContainer->curNum >> 0) & 255;
        charChunkNum[1] = (inContainer->curNum >> 8) & 255;
        charChunkNum[2] = (inContainer->curNum >> 16) & 255;
        charChunkNum[3] = (inContainer->curNum >> 24) & 255;

        uint32_t tmpOffset = 0;
        // 复制chunk数量到outcontainer
        memcpy(outContainer->body + tmpOffset, charChunkNum, 4u);
        // 复制header到outcontainer
        tmpOffset += 4u;
        memcpy(outContainer->body + tmpOffset, inContainer->headerBuf, inContainer->curHeaderSize);
        // 复制chunk到outcontainer
        tmpOffset += inContainer->curHeaderSize;
        memcpy(outContainer->body + tmpOffset, inContainer->buf, inContainer->curSize);
        // 修改size
        tmpOffset += inContainer->curSize;
        outContainer->currentSize = tmpOffset;

        Enclave::Logging(myName_.c_str(), "container full, write container\n");

        //存储container
        Ocall_WriteContainer(upOutSGX->outClient);
        
        // 初始化incontainer
        inContainer->curSize = 0;
        inContainer->curHeaderSize = 0;
        inContainer->curNum = 0;
        // 继续存储该chunk
        // 复制chunk数据到incontainer的buf
        memcpy(inContainer->buf + writeOffset, chunkData, chunkSize);
        // 复制FP到incontainer的headerbuf
        memcpy(inContainer->headerBuf + headerWriteOffset, chunkHash.c_str(), CHUNK_HASH_SIZE);
        headerWriteOffset += CHUNK_HASH_SIZE;
        // 复制chunk偏移和长度到headerbuf
        memcpy(inContainer->headerBuf + headerWriteOffset, charOffset, 4u);
        headerWriteOffset += 4u;
        memcpy(inContainer->headerBuf + headerWriteOffset, charChunkSize, 4u);

        // 复制container ID到entry
        memcpy(edgeContainerName, outContainer->containerID, CONTAINER_ID_LENGTH);

        inContainer->curSize += chunkSize;
        inContainer->curHeaderSize += CHUNK_HASH_SIZE;
        inContainer->curHeaderSize += 8u;
        inContainer->curNum = inContainer->curNum + 1;
    }

    writtenDataSize_ += chunkSize;
    writtenChunkNum_++;

    return ;
}