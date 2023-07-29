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
#include "../../include/cloudIndex.h" 

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
            tool::Logging(myName_.c_str(), "do not need to load the previous index.\n"); 
        } 
    }
    #endif
    tool::Logging(myName_.c_str(), "init the CloudIndex.\n");
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
    // tool::Logging(myName_.c_str(), "========CloudIndex Info========\n");
    // tool::Logging(myName_.c_str(), "logical chunk num: %lu\n", _logicalChunkNum);
    // tool::Logging(myName_.c_str(), "logical data size: %lu\n", _logicalDataSize);
    // tool::Logging(myName_.c_str(), "unique chunk num: %lu\n", _uniqueChunkNum);
    // tool::Logging(myName_.c_str(), "unique data size: %lu\n", _uniqueDataSize);
    // tool::Logging(myName_.c_str(), "compressed data size: %lu\n", _compressedDataSize);
    // tool::Logging(myName_.c_str(), "===================================\n");
}



/**
 * @brief update the file recipe
 * 更新 file recipe 用的 buffer，buffer 满了，就写入 recipe file
 * @param chunkAddrStr the chunk address string
 * @param inRecipe the recipe buffer
 * @param curEdge the current edge var
 */
void CloudIndex::UpdateFileRecipe(string &chunkAddrStr, Recipe_t* inRecipe, 
    EdgeVar* curEdge) {
    memcpy(inRecipe->entryList + inRecipe->recipeNum * sizeof(RecipeEntry_t), 
        chunkAddrStr.c_str(), sizeof(RecipeEntry_t));
    inRecipe->recipeNum++;

    if ((inRecipe->recipeNum % curEdge->sendRecipeBatchSize_) == 0) {
        storageCoreObj_->UpdateRecipeToFile(inRecipe->entryList, 
            inRecipe->recipeNum, curEdge->_recipeWriteHandler);
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
void CloudIndex::ProcessFpOneBatch(SendMsgBuffer_t* recvFpBuf, SendMsgBuffer_t* sendFpBoolBuf, 
EdgeVar* outEdge) {
    uint8_t* fpBuffer = recvFpBuf->dataBuffer;
    uint32_t fpNum = recvFpBuf->header->currentItemNum;
    string tmpFpStr; // 存放每个读出的 Fp
    //TODO: 后续将string修改为char*
    tmpFpStr.resize(CHUNK_HASH_SIZE);
    string tmpChunkAddressStr; // 读入 tmpFpStr 已有的 Container ID / Address
    tmpChunkAddressStr.resize(sizeof(RecipeEntry_t), 0);
    uint32_t currentOffset = 0; // 这里 buffer 从 fpBuffer 开始，不需要考虑 header 的偏移
    uint32_t tmpChunkSize = 0;
    uint8_t* fpBoolBuf = sendFpBoolBuf->dataBuffer;
    sendFpBoolBuf->header->currentItemNum = fpNum;
    sendFpBoolBuf->header->dataSize = fpNum;
    CloudRecipe_t* cloudRecipe = outEdge->_cloudRecipe;
    uint32_t fpCurNum = cloudRecipe->recipeNum; //当前 Recipe 中已记录的 fp 数量（即 FpIdxEntry 数量）
    
    for (uint32_t i = 0; i < fpNum; i++) {
        memcpy((uint8_t*)&tmpFpStr[0], fpBuffer + currentOffset, CHUNK_HASH_SIZE);
        memcpy((uint8_t*)(cloudRecipe->entryList + fpCurNum * sizeof(FpIdxEntry_t)), fpBuffer + currentOffset, CHUNK_HASH_SIZE); 

        if(!indexStore_->Query(tmpFpStr, tmpChunkAddressStr)) { // 非重复块
            fpBoolBuf[i] = 1;
            memcpy((uint8_t*)(
                cloudRecipe->entryList + fpCurNum * sizeof(FpIdxEntry_t) // List 的最新索引地址
                + CHUNK_HASH_SIZE // Fp
                ), (uint8_t*)&tmpChunkAddressStr[0], CONTAINER_ID_LENGTH);
        } else { // 重复块
            // 直接得到对应 Containder ID，存在 tmpChunkAddressStr
            fpBoolBuf[i] = 0;
        }
        fpCurNum++;
        currentOffset += CHUNK_HASH_SIZE;
    }
    cloudRecipe->recipeNum = fpCurNum;
    return ;   
}

/**
 * @brief process the tailed batch when received the end of the recipe flag
 * 收到结束信号的时候，写完
 * @param upOutSGX the pointer to enclave-related var
 */
void CloudIndex::ProcessFpTailBatch(SendMsgBuffer_t* recvFpBuf, SendMsgBuffer_t* sendFpBoolBuf, 
EdgeVar* outEdge) {
    ProcessFpOneBatch(recvFpBuf, sendFpBoolBuf, outEdge);
    return ;
}

void CloudIndex::ProcessChunkOneBatch(SendMsgBuffer_t* recvChunkBuf, EdgeVar* outEdge){
    uint8_t* chunkBuffer = recvChunkBuf->dataBuffer;
    uint32_t chunkNum = recvChunkBuf->header->currentItemNum;
    CloudRecipe_t* cloudRecipe = outEdge->_cloudRecipe;
    uint8_t* FpIdxEntryList = cloudRecipe->entryList;
    uint32_t uniqueFpIdx = cloudRecipe->curIdx; 
    
    uint32_t currentOffset = 0; //recvChunkBuf的当前偏移量
    RecipeEntry_t* chunkAddr = (RecipeEntry_t*)malloc(sizeof(RecipeEntry_t));
    uint8_t* cmpStr = (uint8_t*)malloc(CONTAINER_ID_LENGTH); //用于比较是否为空的临时数组
    memset(cmpStr, 0, CONTAINER_ID_LENGTH);
    string tmpFpStr; // 存放每个读出的 Fp
    //TODO: 后续将string修改为char*
    tmpFpStr.resize(CHUNK_HASH_SIZE); //用于存放 FpIdxEntryList 中的FP
    uint32_t chunkSize = 0; 
    string chunkData;

    for (uint32_t i = 0; i < chunkNum; i++) {
        memcpy(&chunkSize, chunkBuffer + currentOffset, sizeof(uint32_t));

        currentOffset += sizeof(uint32_t);
        chunkData.resize(chunkSize);
        memcpy((uint8_t*)&chunkData[0], chunkBuffer + currentOffset, chunkSize);

        storageCoreObj_->SaveChunk(outEdge, chunkData.c_str(), chunkSize, chunkAddr); //将分配的 CID 及偏移量、长度等存入到 chunkAddr 

        //TODO: 将对应的 RecipeEntry 插入到对应的 FP 索引
        uint8_t flag = 0;
        while(!flag){     
            uint8_t* tmpChunkAddr = FpIdxEntryList + uniqueFpIdx * sizeof(FpIdxEntry_t)  
                            + CHUNK_HASH_SIZE; // 第 uniqueFpIdx 个 entry
            
            if(memcmp(cmpStr, tmpChunkAddr, CONTAINER_ID_LENGTH) == 0){ 
                //说明第 uniqueFpIdx 个 entry 中不含 address，也即找到对应的 unique FP
                memcpy(tmpChunkAddr, chunkAddr, sizeof(RecipeEntry_t)); //将chunkAddr拷贝到entry中的 address
                memcpy((uint8_t*)&tmpFpStr[0], FpIdxEntryList + uniqueFpIdx * sizeof(FpIdxEntry_t), CHUNK_HASH_SIZE); //将 entry 中的 FP 拷贝到临时的 FP 串中
                indexStore_->InsertBuffer(tmpFpStr, (char*)chunkAddr, sizeof(RecipeEntry_t);
                //insert
                flag = 1;
            }
            uniqueFpIdx++;
        }
        currentOffset += chunkSize;
    }
    cloudRecipe->curIdx = uniqueFpIdx;
    free(chunkAddr);
    free(cmpStr);
    return ;
}

void CloudIndex::ProcessChunkTailBatch(SendMsgBuffer_t* recvChunkBuf, EdgeVar* outEdge){
    //ProcessChunkOneBatch(recvChunkBuf, outEdge);
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
    maxBufferSize = tool::sendChunkBatchSize_ * (CHUNK_HASH_SIZE + CONTAINER_ID_LENGTH); // CHUNK_HASH_SIZE + sizeof(RecipeEntry_t)
    tmpBuffer = (uint8_t*) malloc(maxBufferSize);
    itemSize = CloudIndexObj_.size();

    // persist the item number 先存 Fp2Chunk 的数量，方便以后读
    tool::WriteBufferToFile((uint8_t*)&itemSize, sizeof(itemSize), SEALED_BASELINE_INDEX_PATH);

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
            tool::WriteBufferToFile(tmpBuffer, offset, SEALED_BASELINE_INDEX_PATH);
            offset = 0;
        }
    }

    // 写入最后一批不足整个 buffer 的数据
    if (offset != 0) {
        // handle the tail data
        tool::WriteBufferToFile(tmpBuffer, offset, SEALED_BASELINE_INDEX_PATH);
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
    tool::ReadFileToBuffer((uint8_t*)&itemNum, sizeof(itemNum), SEALED_BASELINE_INDEX_PATH); 

    // init buffer
    maxBufferSize = tool::sendChunkBatchSize_ * (CHUNK_HASH_SIZE + CONTAINER_ID_LENGTH);
    tmpBuffer = (uint8_t*) malloc(maxBufferSize);

    size_t expectReadBatchNum = (itemNum / tool::sendChunkBatchSize_); // 期望处理完整批次数量
    for (size_t i = 0; i < expectReadBatchNum; i++) {
        tool::ReadFileToBuffer(tmpBuffer, maxBufferSize, SEALED_BASELINE_INDEX_PATH);
        for (size_t item = 0; item < tool::sendChunkBatchSize_; 
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
        tool::ReadFileToBuffer(tmpBuffer, maxBufferSize, SEALED_BASELINE_INDEX_PATH);
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