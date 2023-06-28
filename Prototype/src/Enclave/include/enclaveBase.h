/**
 * @file enclaveBase.h
 * @author Zuoru YANG (zryang@cse.cuhk.edu.hk)
 * @brief define the interface of enclave base
 * @version 0.1
 * @date 2020-12-28
 * 
 * @copyright Copyright (c) 2020
 * 
 */


#ifndef ENCLAVE_BASE_H
#define ENCLAVE_BASE_H

#include "commonEnclave.h"
#include "ecallEnc.h"
#include "ecallStorage.h"
#include "ecallLz4.h"

#define ENABLE_SEALING 1
static const double SEC_TO_USEC = 1000 * 1000;

class EnclaveClient;

class EnclaveBase {
    protected:
        string myName_ = "EnclaveBase";

        // storage core pointer
        EcallStorageCore* storageCoreObj_;

        // crypto obj inside the enclave 
        EcallCrypto* cryptoObj_;

        // for the limitation 
        uint64_t maxSegmentChunkNum_ = 0;

        /**
         * @brief identify whether it is the end of a segment
         * 
         * @param chunkHashVal the input chunk hash
         * @param chunkSize the input chunk size
         * @param segment the reference to current segment
         * @return true is the end
         * @return false is not the end 
         */
        bool IsEndOfSegment(uint32_t chunkHashVal, uint32_t chunkSize, Segment_t* segment);

        /**
         * @brief convert hash to a value
         * 
         * @param inputHash the input chunk hash
         * @return uint32_t the returned value
         */
        uint32_t ConvertHashToValue(const uint8_t* inputHash);

        /**
         * @brief update the file recipe
         * 
         * @param chunkAddrStr the chunk address string
         * @param inRecipe the in-enclave recipe buffer
         * @param upOutSGX the upload out-enclave var
         */
        void UpdateFileRecipe(string& chunkAddrStr, Recipe_t* inRecipe,
            UpOutSGX_t* upOutSGX);
        
        /**
         * @brief update the file recipe
         * 
         * @param chunkHash the chunk hash
         * @param inRecipe the in-enclave recipe buffer
         * @param upOutSGX the upload out-enclave var
         */
        void UpdateFileRecipeWithMLEKey(string& chunkHash, Recipe_t* inRecipe,
            UpOutSGX_t* upOutSGX);

        /**
         * @brief process an unique chunk
         * 
         * @param chunkAddr the chunk address
         * @param chunkBuffer the chunk buffer
         * @param chunkSize the chunk size
         * @param upOutSGX the upload out-enclave var
         */
        void ProcessUniqueChunk(RecipeEntry_t* chunkAddr, uint8_t* chunkBuffer, 
            uint32_t chunkSize, UpOutSGX_t* upOutSGX);

        /**
         * @brief process an unique chunk with MLE key
         * 
         * @param edgeContainerName the container address
         * @param chunkBuffer the chunk buffer
         * @param chunkSize the chunk size
         * @param upOutSGX the upload out-enclave var
         * @param mleKey MLE Key of an unique chunk
         * @param chunkHash the hash of the chunk
         */
        void ProcessUniqueChunkWithMLEKey(uint8_t* edgeContainerName, uint8_t* chunkBuffer, 
            uint32_t chunkSize, UpOutSGX_t* upOutSGX, uint8_t* mleKey, string chunkHash);

        /**
         * @brief update the index store
         * 
         * @param key the key of the k-v pair 
         * @param buffer the data buffer 
         * @param bufferSize the size of the buffer
         * @return true success
         * @return false fail
         */
        
        bool UpdateIndexStore(const string& key, const char* buffer, 
            size_t bufferSize);

        /**
         * @brief read the information from the index store
         * 
         * @param key key 
         * @param value value
         * @param upOutSGX the upload out-enclave var
         * @return true 
         * @return false 
         */
        bool ReadIndexStore(const string& key, string& value,
            UpOutSGX_t* upOutSGX);

        /**
         * @brief reset the value of current segment
         * 
         * @param sgxClient the to the current client
         */
        void ResetCurrentSegment(EnclaveClient* sgxClient);

        /**
         * @brief Get the Time Differ object
         * 
         * @param sTime the start time
         * @param eTime the end time
         * @return double the diff of time
         */
        double GetTimeDiffer(uint64_t sTime, uint64_t eTime);

    public:
        // for statistic 
uint64_t _logicalChunkNum = 0;
        uint64_t _logicalDataSize = 0;
        uint64_t _uniqueChunkNum = 0;
        uint64_t _uniqueDataSize = 0;
        uint64_t _compressedDataSize = 0;
        uint64_t _refChunkNum = 0;
        uint64_t _deltaChunkNum = 0;
        uint64_t _deltaDataSize = 0;
        uint64_t _deltachunksave = 0;
        uint64_t _indeltanum = 0;
        uint64_t _outdeltanum = 0;


        //record indedup time
        uint64_t _indedupstarttime;
        uint64_t _indedupendtime;
        uint64_t _indeduptime = 0;
        uint64_t _totalindeduptime = 0;
        //record outdeduptime
        uint64_t _outdedupstarttime;
        uint64_t _outdedupendtime;
        uint64_t _outdeduptime = 0;
        uint64_t _totaloutdeduptime = 0;
        //record sf time
        uint64_t _sfstarttime;
        uint64_t _sfendtime;
        uint64_t _sftime = 0;
        uint64_t _totalsftime = 0;
        //record indelta time
        uint64_t _deltastrattime;
        uint64_t _deltaendtime;
        uint64_t _deltatime = 0;
        uint64_t _totaldeltatime = 0;
        //record indelta time
        uint64_t _indeltastrattime;
        uint64_t _indeltaendtime;
        uint64_t _indeltatime = 0;
        uint64_t _totalindeltatime = 0;
        //record outdelta time
        uint64_t _outdeltastrattime;
        uint64_t _outdeltaendtime;
        uint64_t _outdeltatime = 0;
        uint64_t _totaloutdeltatime = 0;
        //record container_cache_I/O
        uint64_t _conI_Ostrattime;
        uint64_t _conI_Oendtime;
        uint64_t _conI_Otime = 0;
        uint64_t _totalconI_Otime = 0;
        //record container_cache update
        uint64_t _conupdatestrattime;
        uint64_t _conupdateendtime;
        uint64_t _conupdatetime = 0;
        uint64_t _totalconupdatetime = 0;
        //record delay time
        uint64_t _delaystrattime;
        uint64_t _delayendtime;
        uint64_t _delaytime = 0;
        uint64_t _totalcondelaytime = 0;
        //record delay update time
        uint64_t _delayupdatestrattime;
        uint64_t _delayupdateendtime;
        uint64_t _delayupdatetime = 0;
        uint64_t _totaldelayupdatetime = 0;
        //record delay process time
        uint64_t _delayprocessstrattime;
        uint64_t _delayprocessendtime;
        uint64_t _delayprocesstime = 0;
        uint64_t _totaldelayprocesstime = 0;
        //record process time;
        uint64_t _processstrattime;
        uint64_t _processendtime;
        uint64_t _processtime = 0;
        uint64_t _totalprocesstime = 0;
        //record delta process time;
        uint64_t _deltaprocessstrattime;
        uint64_t _deltaprocessendtime;
        uint64_t _deltaprocesstime = 0;
        uint64_t _totaldeltaprocesstime = 0;
        //record unique process time;
        uint64_t _uniqueprocessstrattime;
        uint64_t _uniqueprocessendtime;
        uint64_t _uniqueprocesstime = 0;
        uint64_t _totaluniqueprocesstime = 0;
        //unique chunk;
        uint64_t backup_unique = 0;
        uint64_t backup_delta = 0;
        uint64_t backup_indelta = 0;
        uint64_t backup_outdelta = 0;
        uint64_t backup_total_time = 0;
        uint64_t backup_delay_push = 0;
        uint64_t backup_delay_pop= 0;


        //record backup total time
        uint64_t _totalstarttime;
        uint64_t _totalendtime;
        uint64_t backup_enclave_total = 0;



        uint64_t _totaltime = 0;
        uint64_t _encrypttime = 0;
        uint64_t _storetime = 0;
        uint64_t _enclavetime = 0;
        uint64_t _test_flag = 0;
        uint64_t _test_save = 0;
        uint64_t _delay_in_success = 0;
        uint64_t _delay_out_success = 0;
        uint64_t _delay_in_fail = 0;
        uint64_t _ocall_times = 0;

    
#if (SGX_BREAKDOWN == 1)
        uint64_t _startTime;
        uint64_t _endTime;
        uint64_t _dataTransTime = 0;
        uint64_t _dataTransCount= 0;
        uint64_t _fingerprintTime = 0;
        uint64_t _fingerprintCount = 0;
        uint64_t _freqTime = 0;
        uint64_t _freqCount = 0;
        uint64_t _firstDedupTime = 0;
        uint64_t _firstDedupCount = 0;
        uint64_t _secondDedupTime = 0;
        uint64_t _secondDedupCount = 0;
        uint64_t _compressTime = 0;
        uint64_t _compressCount = 0;
        uint64_t _encryptTime = 0;
        uint64_t _encryptCount = 0;
        uint64_t _testOCallTime = 0;
        uint64_t _testOCallCount = 0;
#endif

        /**
         * @brief Construct a new EnclaveBase object
         * 
         */
        EnclaveBase();

        /**
         * @brief Destroy the Enclave Base object
         * 
         */
        virtual ~EnclaveBase();

        /**
         * @brief process one batch
         * 
         * @param recvChunkBuf the recv chunk buffer
         * @param upOutSGX the pointer to enclave-related var 
         */
        virtual void ProcessOneBatch(SendMsgBuffer_t* recvChunkBuf, 
            UpOutSGX_t* upOutSGX) = 0;

        /**
         * @brief process the tailed batch when received the end of the recipe flag
         * 
         * @param upOutSGX the pointer to enclave-related var
         */
        virtual void ProcessTailBatch(UpOutSGX_t* upOutSGX) = 0;
};
#endif