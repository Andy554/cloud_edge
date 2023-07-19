/**
 * @file cloudIndex.h
 * @author Zuoru YANG (zryang@cse.cuhk.edu.hk), modified by cyh
 * @brief define the interface of baseline cloud index
 * @version 0.1
 * @date 2023-05-05
 * 
 * @copyright Copyright (c) 2021
 * 
 */


/* Prototype/include/enclaveIndex.h */
#ifndef ENCLAVE_SIMPLE_H
#define ENCLAVE_SIMPLE_H

#include "absIndex.h"

#include "sgx_urts.h"
#include "sgx_capable.h"
#include "../src/Enclave/include/storeOCall.h"
#include "../build/src/Enclave/storeEnclave_u.h"

class CloudIndex : public AbsIndex {
    private:
        string myName_ = "CloudIndex";
        // the variable to record the enclave information
        // sgx_enclave_id_t eidSGX_;
    public:
        /**
         * @brief Construct a new Enclave Simple Index object
         * 数据库本身实现了 从文件读写 fp2chunk.
         * @param indexStore the reference to the index store
         * @param indexType the type of index
         * @param eidSGX the enclave id
         */
        CloudIndex(AbsDatabase* indexStore/*, int indexType, sgx_enclave_id_t eidSGX*/);

        /**
         * @brief Destroy the Enclave Simple Index object
         * 
         */
        ~CloudIndex();

        /**
         * @brief process FingerPrint one batch 
         * 接受来自 Edge 的 FpBuf，一个个检查 Fp 是否是重复块指纹，将查询结果放入sendFpBoolBuf，
         * 通过 sendFpBoolBuf 发送给 edge。
         * @param recvFpBuf the recv Fp buffer
         * @param sendFpBoolBuf the send Fp bool buffer
         * @param upOutSGX the structure to store the enclave related variable
         */
        void CloudIndex::ProcessFpOneBatch(SendMsgBuffer_t* recvFpBuf, SendMsgBuffer_t* sendFpBoolBuf, 
            RecipeEntry_1_t* fp2CidArr, uint64_t& fpCurNum)

        /**
         * @brief process FingerPrint one batch 
         * 处理最后一批来自 Edge 的 FpBuf
         * @param recvFpBuf the recv Fp buffer
         * @param sendFpBoolBuf the send Fp bool buffer
         * @param upOutSGX the structure to store the enclave related variable
         */
        void CloudIndex::ProcessFpTailBatch(SendMsgBuffer_t* recvFpBuf, SendMsgBuffer_t* sendFpBoolBuf, 
            RecipeEntry_1_t* fp2CidArr, uint64_t& fpCurNum) 


        /**
         * @brief process one batch 
         * 
         * @param recvChunkBuf the recv chunk buffer
         * @param upOutSGX the structure to store the enclave related variable
         */
        void ProcessOneBatch(SendMsgBuffer_t* recvChunkBuf, UpOutSGX_t* upOutSGX){};

        /**
         * @brief process the tail segment
         * 
         * @param upOutSGX the structure to store the enclave related variable
         */
        void ProcessTailBatch(UpOutSGX_t* upOutSGX){};
};
#endif



/* Prototype/src/Enclave/include/ecallInEnclave.h */
// #ifndef CLOUD_BASE_LINE
// #define CLOUD_BASE_LINE
#ifdef CLOUD_BASE_LINE
#define ENABLE_SEALING 1 // 是否使用文件存储

#include "enclaveBase.h"
// base : Prototype/src/Enclave/include/ecallInEnclave.h -> Prototype/src/Enclave/include/enclaveBase.h
#include "commonCloud.h" // namespace 
// base : #include "commonEnclave.h" 

#define SEALED_BASELINE_INDEX_PATH "cloud-baseline-seal-index" // "baseline-seal-index"

// TODO 考虑 Prototype/include/enclaveIndex.h 继承 AbsIndex
class CloudIndex : public CLoudBase {
    private:
        string myName_ = "CloudIndex";
        unordered_map<string, string> CloudIndexObj_; // <chunkFp, containerID>

        // for persistence
        // ?文件读写参考/直接调用? Prototype/src/Enclave/include/storeOCall.h
        // Prototype/src/Enclave/ocallSrc/storeOCall.cc
        // extern ofstream outSealedFile_; // 输出文件流
        // extern ifstream inSealedFile_; // 输入文件流

        /**
         * @brief 查询是否存在 fp idx
         *  不存在需要后续接收 chunk 时，载入 container 对应的 ID
         *      CloudIndexObj_.insert({keyStr, valueStr});
         * @param recvFpBuf the recv Fp buffer
         * @return 上传 fp 是否存在
         */
        std::vector<bool> QueryFpIndex(SendMsgBuffer_t* recvFpBuf);

        /**
         * @brief persist the deduplication index to the disk
         *      memcpy() f.write
         * @return true success
         * @return false fail
         */
        bool PersistDedupIndex();

        /**
         * @brief read the hook index from sealed data
         *      memcpy() f.read
         * @return true success
         * @return false fail
         */
        bool LoadDedupIndex();

    public:

        /**
         * @brief Construct a new FingerPrint Index object
         * 
         */
        CloudIndex();

        /**
         * @brief Destroy the FingerPrint Index object
         * 
         */
        ~CloudIndex();

        /**
         * @brief process one batch
         * 
         * @param recvFpBuf the recv chunk buffer
         * @param upOutSGX the pointer to enclave-related var
         */
        void ProcessOneBatch(SendMsgBuffer_t* recvFpBuf, UpOutSGX_t* upOutSGX);

        /**
         * @brief process the tailed batch when received the end of the recipe flag
         * 
         * @param upOutSGX the pointer to enclave-related var
         */
        void ProcessTailBatch(UpOutSGX_t* upOutSGX);
};
#endif