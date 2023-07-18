/**
 * @file ecallBaseline.cc
 * @author Zuoru YANG (zryang@cse.cuhk.edu.hk)
 * @brief implement the interface of baseline index
 * base : Prototype/src/Enclave/ecallSrc/ecallIndex/ecallInEnclave.cc
 * @version 0.1
 * @date 2023-05-05
 * 
 * @copyright Copyright (c) 2021
 * 
 */
// #include "leveldbDatabase.h"
// #include "inMemoryDatabase.h"
#include "cloudIndex.h" 

// TODO: 将 Baseline/src/Server/storageCore.cc 适用于Container的新设计：WriteContainer()、SaveChunk()
// TODO：对 ProcessOneBatch 中进行修改，它调用了 ProcessUniqueChunk() -> SaveChunk() -> WriteContainer()，与我们的设计不太一致

// TODO enclave 有 namespace Enclave/OutEnclave，Cloud 以哪个为模板？
// src
// Prototype/src/Enclave/include/commonEnclave.h
// Prototype/src/Enclave/ecallSrc/ecallUtil/commonEnclave.cc
// modify
// Prototype/src/Cloud/commonCloud.h
// Prototype/src/Cloud/commonCloud.cc
// namespace : Enclave -> Cloud
// ? namespace Cloud 参考 Enclave/OutEnclave，但是都是用来 持久化存储/读入内存,
// ? 现在考虑继承 AbsIndex，实现 Cloud，本身有成员变量 AbsDatabase(InMemoryDatabase)
// ? Fp2ChunkDB，这个数据库 持久化存储/读入内存/查询/插入/修改 均已实现，不需要再重新写过。
// ? 所以 commonCloud/cloudBase 不再需要；选择使用 absIndex + inMemoryDatabase
// ? Baseline/src/Index/absIndex.cc + Prototype/src/Database/inMemoryDatabase.cc

// TODO 参考 Baseline/src/Index/absIndex.cc 实现 构造/析构函数
/**
 * @brief Construct a new FingerPrint Index object
 * 
 */
CloudIndex::CloudIndex(AbsDatabase* indexStore) : AbsIndex(indexStore) {
    #ifdef CLOUD_BASE_LINE
    if (ENABLE_SEALING) {
        if (!this->LoadDedupIndex()) {
            Cloud::Logging(myName_.c_str(), "do not need to load the previous index.\n"); 
        } 
    }
    #endif
    Cloud::Logging(myName_.c_str(), "init the CloudIndex.\n");
}

/**
 * @brief Destroy the FingerPrint Index object
 * 
 */
CloudIndex::~CloudIndex() {
    #ifdef CLOUD_BASE_LINE
    if (ENABLE_SEALING) {
        this->PersistDedupIndex();
    }
    #endif
    Cloud::Logging(myName_.c_str(), "========CloudIndex Info========\n");
    Cloud::Logging(myName_.c_str(), "logical chunk num: %lu\n", _logicalChunkNum);
    Cloud::Logging(myName_.c_str(), "logical data size: %lu\n", _logicalDataSize);
    Cloud::Logging(myName_.c_str(), "unique chunk num: %lu\n", _uniqueChunkNum);
    Cloud::Logging(myName_.c_str(), "unique data size: %lu\n", _uniqueDataSize);
    Cloud::Logging(myName_.c_str(), "compressed data size: %lu\n", _compressedDataSize);
    Cloud::Logging(myName_.c_str(), "===================================\n");
}



/**
 * @brief update the file recipe
 * 更新 file recipe 用的 buffer，buffer 满了，就写入 recipe file
 * @param chunkAddrStr the chunk address string
 * @param inRecipe the recipe buffer
 * @param curClient the current client var
 */
void CloudIndex::UpdateFileRecipe(string &chunkAddrStr, Recipe_t* inRecipe, 
    ClientVar* curClient) {
    memcpy(inRecipe->entryList + inRecipe->recipeNum * sizeof(RecipeEntry_t), 
        chunkAddrStr.c_str(), sizeof(RecipeEntry_t));
    inRecipe->recipeNum++;

    if ((inRecipe->recipeNum % sendRecipeBatchSize_) == 0) {
        storageCoreObj_->UpdateRecipeToFile(inRecipe->entryList, 
            inRecipe->recipeNum, curClient->_recipeWriteHandler);
        inRecipe->recipeNum = 0; 
    }
    return ;
}

/**
 * @brief process FingerPrint one batch 
 * 接受来自 Edge 的 FpBuf，一个个检查 Fp 是否是重复块指纹，将非重复块的指纹，打包到MessageQueue，
 * 通过 SendBuf 发送给 edge。
 * 同时将 Fp2Chunk 记录为 fileRecipe
 * @param recvFpBuf the recv Fp buffer
 * @param upOutSGX the structure to store the enclave related variable
 */
void CloudIndex::ProcessFpOneBatch(SendFpBuffer_t* recvFpBuf, 
    UpOutSGX_t* upOutSGX) {
    // sendBuffer = header + fpBuffer
    uint8_t* recvBuffer = recvFpBuf->fpBuffer; // data 从 fp 直接开始读，不需要考虑 header 的偏移
    // get the fp num 当前批次 fp num 
    uint32_t fpNum = recvFpBuf->header->currentItemNum;

    // start to process each fp
    string tmpFpStr; // 存放每个读出的 Fp
    tmpFpStr.resize(CHUNK_HASH_SIZE, 0); //? 不直接用 uint8_t*，是为了避免 free 吗；还是因为 db 的 key/value 都是 string? Prototype/src/Database/leveldbDatabase.cc
    string tmpChunkAddressStr; // 读入 tmpFpStr 已有的 Container ID / Address
    tmpChunkAddressStr.resize(CONTAINER_ID_LENGTH, 0);
    size_t currentOffset = 0; // 这里 buffer 从 fpBuffer 开始，不需要考虑 header 的偏移
    uint32_t tmpChunkSize = 0;

    // 读 fp -> recvBuffer
    for (size_t i = 0; i < fpNum; i++) {
        // compute the hash over the plaintext chunk
        // get tmpFpStr from buffer
        memcpy((uint8_t*)&tmpFpStr[0], recvBuffer + currentOffset, CHUNK_HASH_SIZE);
        currentOffset += CHUNK_HASH_SIZE;

        if(!indexStore_.Query(tmpFpStr, tmpChunkAddressStr)) { // 非重复块
            // 存起来，发给 Edge，等得到 chunk 的时候，再插入fp2chunk数据库 Insert(fp, containerID)
            // TODO 消息队列的处理，得模仿 client
            MQ.push(tmpFpStr); //? 先存入 MessageQueue
        } else { // 重复块
            // 直接得到对应 Containder ID，存在 tmpChunkAddressStr
        }

        // TODO Fp 存入 file recipe
        this->UpdateFileRecipe(tmpChunkAddressStr, inRecipe, upOutSGX);
    }
    return ;   
}

/**
 * @brief process the tailed batch when received the end of the recipe flag
 * 收到结束信号的时候，写完
 * @param upOutSGX the pointer to enclave-related var
 */
void CloudIndex::ProcessFpTailBatch(UpOutSGX_t* upOutSGX) {
    // the in-enclave info
    EnclaveClient* sgxClient = (EnclaveClient*)upOutSGX->sgxClient;
    Recipe_t* inRecipe = &sgxClient->_inRecipe;
    EVP_CIPHER_CTX* cipherCtx = sgxClient->_cipherCtx;
    uint8_t* masterKey = sgxClient->_masterKey;

    if (inRecipe->recipeNum != 0) {
        // the out-enclave info
        Recipe_t* outRecipe = (Recipe_t*)upOutSGX->outRecipe;
        cryptoObj_->EncryptWithKey(cipherCtx, inRecipe->entryList,
            inRecipe->recipeNum * CONTAINER_ID_LENGTH, masterKey, 
            outRecipe->entryList);
        outRecipe->recipeNum = inRecipe->recipeNum;
        Ocall_UpdateFileRecipe(upOutSGX->outClient);
        inRecipe->recipeNum = 0;
    }

    if (sgxClient->_inContainer.curSize != 0) {
        memcpy(upOutSGX->curContainer->body, sgxClient->_inContainer.buf,
            sgxClient->_inContainer.curSize);
        upOutSGX->curContainer->currentSize = sgxClient->_inContainer.curSize;
    }
    return ;
}

// TODO 以下暂时不需要管

/*
看了 Baseline/src/Index/absIndex.cc，相比 Prototype/src/Index/absIndex.cc，主要多了
- ProcessUniqueChunk 压缩 chunk，这块由edge负责，cloud不需要
- UpdateFileRecipe 更新 file recipe 用的 buffer，满了就写一批到 recipe file，可以放在 cloud index

*/
// base : Baseline/src/Index/absIndex.cc
#ifdef BaselineAbsIndex
/**
 * @brief process one unique chunk
 * 压缩 chunk
 * @param chunkAddr the chunk address
 * @param chunkBuffer the chunk buffer
 * @param chunkSize the chunk size
 * @param curClient the current client var
 */
void AbsIndex::ProcessUniqueChunk(RecipeEntry_t* chunkAddr, uint8_t* chunkBuffer,
    uint32_t chunkSize, ClientVar* curClient) {
    uint8_t tmpCompressedChunk[MAX_CHUNK_SIZE];
    int tmpCompressedChunkSize = 0;
    tmpCompressedChunkSize = LZ4_compress_fast((char*)(chunkBuffer), (char*)tmpCompressedChunk,
        chunkSize, chunkSize, 3);
    
    if (tmpCompressedChunkSize > 0) {
        // it can be compressed
        _compressedDataSize += tmpCompressedChunkSize;
    } else {
        // it cannot be compressed
        _compressedDataSize += chunkSize;
        tmpCompressedChunkSize = chunkSize;

        memcpy(tmpCompressedChunk, chunkBuffer, tmpCompressedChunkSize);
    }

    // finish the compression, assign this a container
    storageCoreObj_->SaveChunk((char*)tmpCompressedChunk, tmpCompressedChunkSize, 
        chunkAddr, curClient);
    return ;
}

/**
 * @brief update the file recipe
 * 更新 file recipe 用的 buffer，满了就写一批到 recipe file
 * @param chunkAddrStr the chunk address string
 * @param inRecipe the recipe buffer
 * @param curClient the current client var
 */
void AbsIndex::UpdateFileRecipe(string &chunkAddrStr, Recipe_t* inRecipe, 
    ClientVar* curClient) {
    memcpy(inRecipe->entryList + inRecipe->recipeNum * sizeof(RecipeEntry_t), 
        chunkAddrStr.c_str(), sizeof(RecipeEntry_t));
    inRecipe->recipeNum++;

    if ((inRecipe->recipeNum % sendRecipeBatchSize_) == 0) {
        storageCoreObj_->UpdateRecipeToFile(inRecipe->entryList, 
            inRecipe->recipeNum, curClient->_recipeWriteHandler);
        inRecipe->recipeNum = 0; 
    }
    return ;
}
#endif

#ifdef enclaveIndex
/**
 * @brief process one batch
 * 原 server 数据直接交给 enclave 处理，现 cloud 当场处理
 * 
 * @param buffer the input buffer
 * @param payloadSize the payload size
 * @param upOutSGX the pointer to enclave-related var
 */
void CloudIndex::ProcessOneBatch(SendMsgBuffer_t* recvFpBuf,
    UpOutSGX_t* upOutSGX) {
    // the in-enclave info
    EnclaveClient* sgxClient = (EnclaveClient*)upOutSGX->sgxClient; // Prototype/src/Enclave/include/ecallClient.h
    EVP_CIPHER_CTX* cipherCtx = sgxClient->_cipherCtx;
    EVP_MD_CTX* mdCtx = sgxClient->_mdCtx;
    uint8_t* recvBuffer = sgxClient->_recvBuffer; // ? 数据怎么是用 upOutSGX->sgxClient->_recvBuffer 携带的？？？ EnclaveClient 负责 free
    uint8_t* sessionKey = sgxClient->_sessionKey;
    Recipe_t* inRecipe = &sgxClient->_inRecipe;
    
    // decrypt the received data with the session key
    cryptoObj_->SessionKeyDec(cipherCtx, recvFpBuf->dataBuffer,
        recvFpBuf->header->dataSize, sessionKey, recvBuffer);

    // get the fp num 当前批次 fp num 
    uint32_t chunkNum = recvFpBuf->header->currentItemNum; // SendMsgBuffer_t : Baseline/include/chunkStructure.h

    // start to process each chunk
    string tmpChunkAddressStr;
    tmpChunkAddressStr.resize(CONTAINER_ID_LENGTH, 0);
    size_t currentOffset = 0; // 这里 buffer 是否需要考虑 header 的偏移
    uint32_t tmpChunkSize = 0;
    string tmpHashStr;
    tmpHashStr.resize(CHUNK_HASH_SIZE, 0);

    // 读 fp -> recvBuffer
    for (size_t i = 0; i < chunkNum; i++) {
        // compute the hash over the plaintext chunk
        memcpy(&tmpChunkSize, recvBuffer + currentOffset, sizeof(uint32_t)); // 得到 chunk 大小
        currentOffset += sizeof(uint32_t); // 指向实际的chunk

        cryptoObj_->GenerateHash(mdCtx, recvBuffer + currentOffset, 
            tmpChunkSize, (uint8_t*)&tmpHashStr[0]); // 生成 hash，存到 tmpHashStr
        
        if (CloudIndexObj_.count(tmpHashStr) != 0) {
            // it is duplicate chunk
            tmpChunkAddressStr.assign(CloudIndexObj_[tmpHashStr]); // 重复块直接读 container id
        } else {
            // it is unique chunk
            _uniqueChunkNum++;
            _uniqueDataSize += tmpChunkSize;

            // process one unique chunk
            this->ProcessUniqueChunk((RecipeEntry_t*)&tmpChunkAddressStr[0], 
                recvBuffer + currentOffset, tmpChunkSize, upOutSGX); // 非重复块，分配新的 containerid

            // update the index 
            CloudIndexObj_[tmpHashStr] = tmpChunkAddressStr;
        }

        this->UpdateFileRecipe(tmpChunkAddressStr, inRecipe, upOutSGX);
        currentOffset += tmpChunkSize;

        // update the statistic
        _logicalDataSize += tmpChunkSize;
        _logicalChunkNum++;
    }

    return ;
}

/**
 * @brief process the tailed batch when received the end of the recipe flag
 * 
 * @param upOutSGX the pointer to enclave-related var
 */
void CloudIndex::ProcessTailBatch(UpOutSGX_t* upOutSGX) {
    // the in-enclave info
    EnclaveClient* sgxClient = (EnclaveClient*)upOutSGX->sgxClient;
    Recipe_t* inRecipe = &sgxClient->_inRecipe;
    EVP_CIPHER_CTX* cipherCtx = sgxClient->_cipherCtx;
    uint8_t* masterKey = sgxClient->_masterKey;

    if (inRecipe->recipeNum != 0) {
        // the out-enclave info
        Recipe_t* outRecipe = (Recipe_t*)upOutSGX->outRecipe;
        cryptoObj_->EncryptWithKey(cipherCtx, inRecipe->entryList,
            inRecipe->recipeNum * CONTAINER_ID_LENGTH, masterKey, 
            outRecipe->entryList);
        outRecipe->recipeNum = inRecipe->recipeNum;
        Ocall_UpdateFileRecipe(upOutSGX->outClient);
        inRecipe->recipeNum = 0;
    }

    if (sgxClient->_inContainer.curSize != 0) {
        memcpy(upOutSGX->curContainer->body, sgxClient->_inContainer.buf,
            sgxClient->_inContainer.curSize);
        upOutSGX->curContainer->currentSize = sgxClient->_inContainer.curSize;
    }

    return ;
}
#endif

#ifdef CLOUD_BASE_LINE
/**
 * @brief persist the deduplication index to the disk
 * 
 * @return true success
 * @return false fail
 */
bool CloudIndex::PersistDedupIndex() {
    size_t offset = 0;
    bool persistenceStatus = false;
    uint8_t* tmpBuffer;
    size_t itemSize = 0; // Fp2Chunk num
    size_t maxBufferSize;

    // persist the index
    // init the file output stream : Prototype/src/Enclave/ocallSrc/storeOCall.cc
    Ocall_InitWriteSealedFile(&persistenceStatus, SEALED_BASELINE_INDEX_PATH);
    if (persistenceStatus == false) { // 初始化文件输出流失败
        Ocall_SGX_Exit_Error("CloudIndex: cannot init the index sealed file.");
        return false; // added 2023/05/05
    }
    
    // init buffer
    maxBufferSize = Cloud::sendChunkBatchSize_ * (CHUNK_HASH_SIZE + CONTAINER_ID_LENGTH); // CHUNK_HASH_SIZE + sizeof(RecipeEntry_t)
    tmpBuffer = (uint8_t*) malloc(maxBufferSize);
    itemSize = CloudIndexObj_.size();

    // persist the item number 先存 Fp2Chunk 的数量，方便以后读
    Cloud::WriteBufferToFile((uint8_t*)&itemSize, sizeof(itemSize), SEALED_BASELINE_INDEX_PATH);

    // start to persist the index item 再按预设buffer大小，分批写入数据
    for (auto it = CloudIndexObj_.begin(); it != CloudIndexObj_.end(); it++) {
        // fp
        memcpy(tmpBuffer + offset, it->first.c_str(), CHUNK_HASH_SIZE);
        offset += CHUNK_HASH_SIZE;
        // container address
        memcpy(tmpBuffer + offset, it->second.c_str(), CONTAINER_ID_LENGTH);
        offset += CONTAINER_ID_LENGTH;
        if (offset == maxBufferSize) {
            // the buffer is full, write to the file
            Cloud::WriteBufferToFile(tmpBuffer, offset, SEALED_BASELINE_INDEX_PATH);
            offset = 0;
        }
    }

    // 写入最后一批不足整个 buffer 的数据
    if (offset != 0) {
        // handle the tail data
        Cloud::WriteBufferToFile(tmpBuffer, offset, SEALED_BASELINE_INDEX_PATH);
        offset = 0;
    }

    // 关闭文件输出流，释放buffer
    Ocall_CloseWriteSealedFile(SEALED_BASELINE_INDEX_PATH);
    free(tmpBuffer);
    return true;
}

/**
 * @brief read the hook index from sealed data
 * 
 * @return true success
 * @return false fail
 */
bool CloudIndex::LoadDedupIndex() {
    size_t itemNum; // Fp2Chunk num
    string keyStr; // fp
    keyStr.resize(CHUNK_HASH_SIZE, 0);
    string valueStr; // container id
    valueStr.resize(CONTAINER_ID_LENGTH, 0); 
    size_t offset = 0;
    size_t maxBufferSize = 0;
    uint8_t* tmpBuffer;

    size_t sealedDataSize; // 文件大小
    Ocall_InitReadSealedFile(&sealedDataSize, SEALED_BASELINE_INDEX_PATH); 
    if (sealedDataSize == 0) { // 文件大小为0，写入失败
        return false;
    }

    // read the item number; 先读 Fp2Chunk num
    Cloud::ReadFileToBuffer((uint8_t*)&itemNum, sizeof(itemNum), SEALED_BASELINE_INDEX_PATH); 

    // init buffer
    maxBufferSize = Cloud::sendChunkBatchSize_ * (CHUNK_HASH_SIZE + CONTAINER_ID_LENGTH);
    tmpBuffer = (uint8_t*) malloc(maxBufferSize);

    size_t expectReadBatchNum = (itemNum / Cloud::sendChunkBatchSize_); // 期望处理完整批次数量
    for (size_t i = 0; i < expectReadBatchNum; i++) {
        Cloud::ReadFileToBuffer(tmpBuffer, maxBufferSize, SEALED_BASELINE_INDEX_PATH);
        for (size_t item = 0; item < Cloud::sendChunkBatchSize_; 
            item++) {
            memcpy(&keyStr[0], tmpBuffer + offset, CHUNK_HASH_SIZE);
            offset += CHUNK_HASH_SIZE;
            memcpy(&valueStr[0], tmpBuffer + offset, CONTAINER_ID_LENGTH);
            offset += CONTAINER_ID_LENGTH;

            // update the index
            CloudIndexObj_.insert({keyStr, valueStr});
        } 
        offset = 0;
    }

    // 处理不足一个完整批次的数据
    size_t remainItemNum = itemNum - CloudIndexObj_.size();
    if (remainItemNum != 0) {
        Cloud::ReadFileToBuffer(tmpBuffer, maxBufferSize, SEALED_BASELINE_INDEX_PATH);
        for (size_t i = 0; i < remainItemNum; i++) {
            memcpy(&keyStr[0], tmpBuffer + offset, CHUNK_HASH_SIZE);
            offset += CHUNK_HASH_SIZE;
            memcpy(&valueStr[0], tmpBuffer + offset, CONTAINER_ID_LENGTH);
            offset += CONTAINER_ID_LENGTH;  

            // update the index
            CloudIndexObj_.insert({keyStr, valueStr});
        }
        offset = 0;
    }

    // 关闭文件输入流，释放 buffer
    Ocall_CloseReadSealedFile(SEALED_BASELINE_INDEX_PATH);
    free(tmpBuffer);

    // check the index size consistency 
    if (CloudIndexObj_.size() != itemNum) {
        Ocall_SGX_Exit_Error("CloudIndex: load the index error.");
    }
    return true;
}
#endif