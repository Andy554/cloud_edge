/**
 * @file cloudOptThread.cc
 * @author zwx, cyh
 * @brief cloud main thread
 * @version 0.1
 * @date 2023-07-14
 * 
 * @copyright Copyright (c) 2021
 * 
 */

#include "../../include/cloudOptThread.h"

/**
 * @brief Construct a new Cloud Opt Thread object
 * 
 * @param dataSecureChannel data security communication channel
 * @param fp2ChunkDB the index
 * @param eidSGX sgx enclave id
 * @param indexType 
 */
CloudOptThread::CloudOptThread(SSLConnection* dataSecureChannel, 
    AbsDatabase* fp2ChunkDB, sgx_enclave_id_t eidSGX, int indexType) {
    dataSecureChannel_ = dataSecureChannel;
    fp2ChunkDB_ = fp2ChunkDB;
    eidSGX_ = eidSGX;
    indexType_ = indexType;        

    // init the upload
    dataWriterObj_ = new DataWriter();
    storageCoreObj_ = new StorageCore();
    absIndexObj_ = new CloudIndex(fp2ChunkDB_);
    absIndexObj_->SetStorageCoreObj(storageCoreObj_);
    dataReceiverObj_ = new DataReceiver(absIndexObj_, dataSecureChannel_);
    dataReceiverObj_->SetStorageCoreObj(storageCoreObj_);

    // init the restore
    recvDecoderObj_ = new EnclaveRecvDecoder(dataSecureChannel_, 
        eidSGX_);

    // init the RA 
    raUtil_ = new RAUtil(dataSecureChannel_);

    // init the out-enclave var
    OutEnclave::Init(dataWriterObj_, fp2ChunkDB_, storageCoreObj_,
        recvDecoderObj_);

    // for log file
    if (!tool::FileExist(logFileName_)) {
        // if the log file not exist, add the header
        logFile_.open(logFileName_, ios_base::out);
        logFile_ << "logical data size (B), " << "logical chunk num, "
            << "unique data size (B), " << "unique chunk num, "
            << "compressed data size (B), " << "total process time (s), "
            << "enclave speed (MiB/s)" << endl;
    } else {
        // the log file exists
        logFile_.open(logFileName_, ios_base::app | ios_base::out);
    }

    tool::Logging(myName_.c_str(), "init the CloudOptThread.\n");
}   

/**
 * @brief Destroy the Cloud Opt Thread object
 * 
 */
CloudOptThread::~CloudOptThread() {
    OutEnclave::Destroy();
    delete dataWriterObj_;
    delete storageCoreObj_;
    delete absIndexObj_;
    delete dataReceiverObj_;
    delete recvDecoderObj_;
    delete raUtil_;

    for (auto it : clientLockIndex_) {
        delete it.second;
    }

    // destroy the variables inside the enclave
    Ecall_Destroy_Restore(eidSGX_);
    Ecall_Destroy_Upload(eidSGX_);
    logFile_.close();

    fprintf(stderr, "=========CloudOptThread Info========\n");
    fprintf(stderr, "total recv upload requests: %lu\n", totalUploadReqNum_);
    fprintf(stderr, "total recv download requests: %lu\n", totalRestoreReqNum_);
    fprintf(stderr, "====================================\n");
}

/**
 * @brief the main process
 * 
 * @param edgeSSL the client ssl
 */
void CloudOptThread::Run(SSL* edgeSSL) {
    boost::thread* thTmp;
    boost::thread_attributes attrs;
    attrs.set_stack_size(THREAD_STACK_SIZE);
    vector<boost::thread*> thList;
    CloudInfo_t cloudInfo;

    SendMsgBuffer_t recvBuf;
    recvBuf.sendBuffer = (uint8_t*) malloc(sizeof(NetworkHead_t) + 
        CHUNK_HASH_SIZE + sizeof(FileRecipeHead_t)); // 文件名哈希值 + 存储*fp的FileRecipe
    recvBuf.header = (NetworkHead_t*) recvBuf.sendBuffer;
    recvBuf.header->dataSize = 0;
    recvBuf.dataBuffer = recvBuf.sendBuffer + sizeof(NetworkHead_t);
    uint32_t recvSize = 0;

    tool::Logging(myName_.c_str(), "the main thread is running.\n");

    // 不需要RA、Session Key的交互

    if (!dataSecureChannel_->ReceiveData(edgeSSL, recvBuf.sendBuffer, 
        recvSize)) {
        tool::Logging(myName_.c_str(), "recv the edge upload login request error.\n");
        exit(EXIT_FAILURE);
    }

    // check the client lock here (ensure exist only one client with the same client ID)
    uint32_t edgeID = recvBuf.header->clientID;
    boost::mutex* tmpLock;
    {
        lock_guard<mutex> lock(clientLockSetLock_);
        auto clientLockRes = clientLockIndex_.find(edgeID);
        if (clientLockRes != clientLockIndex_.end()) {
            // try to lock this mutex
            tmpLock = clientLockIndex_[edgeID];
            tmpLock->lock();
        } else {
            // add a new lock to the current index
            tmpLock = new boost::mutex();
            clientLockIndex_[edgeID] = tmpLock;
            tmpLock->lock();
        }
    }

    // ---- the main process ----
    int optType = 0;
    switch (recvBuf.header->messageType) {
        case EDGE_LOGIN_UPLOAD: {
            optType = UPLOAD_OPT;
            break;
        }
        case EDGE_LOGIN_DOWNLOAD: {
            optType = DOWNLOAD_OPT;
            break;
        }
        default: {
            tool::Logging(myName_.c_str(), "wrong edge login type.\n");
            exit(EXIT_FAILURE);
        }
    }

    // check the file status
    // convert the file name hash to the file path
    
    char fileHashBuf[CHUNK_HASH_SIZE * 2 + 1];
    for (uint32_t i = 0; i < CHUNK_HASH_SIZE; i++) {
        sprintf(fileHashBuf + i * 2, "%02x", recvBuf.dataBuffer[i]);
    }
    string fileName;
    fileName.assign(fileHashBuf, CHUNK_HASH_SIZE * 2);
    string upRecipePath = config.GetUpRecipeRootPath() +
        fileName + config.GetRecipeSuffix();
    if (!this->CheckFileStatus(upRecipePath, optType)) {
        recvBuf.header->messageType = CLOUD_FILE_NON_EXIST;
        if (!dataSecureChannel_->SendData(edgeSSL, recvBuf.sendBuffer,
            sizeof(NetworkHead_t))) {
            tool::Logging(myName_.c_str(), "send the file not exist reply error.\n");
            exit(EXIT_FAILURE);
        }
        
        // wait the edge to close the connection
        if (!dataSecureChannel_->ReceiveData(edgeSSL, 
            recvBuf.sendBuffer, recvSize)) {
            tool::Logging(myName_.c_str(), "edge close the socket connection.\n");
            dataSecureChannel_->ClearAcceptedClientSd(edgeSSL);
        } else {
            tool::Logging(myName_.c_str(), "edge does not close the connection.\n");
            exit(EXIT_FAILURE);
        }

        // clear the tmp variable
        free(recvBuf.sendBuffer);
        tmpLock->unlock();
        return ;
    } else {
        tool::Logging(myName_.c_str(), "file status check successfully.\n");
    }
    /// check done

    // init the vars for this edge
    EdgeVar* outEdge;
    switch (optType) {
        case UPLOAD_OPT: {
            // update the req number
            totalUploadReqNum_++;
            tool::Logging(myName_.c_str(), "recv the upload request from edge: %u\n",
                edgeID);
            outEdge = new EdgeVar(edgeID, edgeSSL, UPLOAD_OPT, upRecipePath);
            // Ecall_Init_Client(eidSGX_, edgeID, indexType_, UPLOAD_OPT, 
            //     recvBuf.dataBuffer + CHUNK_HASH_SIZE, 
            //     &outEdge->_upOutSGX.sgxClient);

            // EDGE_LOGIN_UPLOAD 首先会上传一次 file recipe
            if(recvBuf.header->dataSize == CHUNK_HASH_SIZE + sizeof(FileRecipeHead_t)) {
                FileRecipeHead_t* fileRecipeHead = recvBuf.dataBuffer + CHUNK_HASH_SIZE; // 通过 recvBuf free，所以实际释放该指针是设为 NULL
                tool::Logging(myName_.c_str(), "find file recipe head. file size : %llu, total chunk num : %llu\n", fileRecipeHead->fileSize, fileRecipeHead->totalChunkNum);
                outEdge->_uploadChunkNum = fileRecipeHead->totalChunkNum;
                fileRecipeHead = NULL;
            } else { // read FileRecipeHead_t 失败
                tool::Logging(myName_.c_str(), "clouldn't find file recipe head.\n");
                exit(EXIT_FAILURE);
            }

            thTmp = new boost::thread(attrs, boost::bind(&DataReceiver::Run, dataReceiverObj_,
                outEdge, &cloudInfo));
            thList.push_back(thTmp); 
#if (MULTI_CLIENT == 0)
            thTmp = new boost::thread(attrs, boost::bind(&DataWriter::Run, dataWriterObj_,
                outEdge->_inputMQ));
            thList.push_back(thTmp);
#endif
            // send the upload-response to the cloud
            recvBuf.header->messageType = CLOUD_LOGIN_RESPONSE;
            if (!dataSecureChannel_->SendData(edgeSSL, recvBuf.sendBuffer, 
                sizeof(NetworkHead_t))) {
                tool::Logging(myName_.c_str(), "send the upload-login response error.\n");
                exit(EXIT_FAILURE);
            }
            break;
        }
        case DOWNLOAD_OPT: {
            // update the req number 
            totalRestoreReqNum_++;
            tool::Logging(myName_.c_str(), "recv the restore request from client: %u\n",
                edgeID);
            outEdge = new EdgeVar(edgeID, edgeSSL, DOWNLOAD_OPT, upRecipePath);
            // Ecall_Init_Client(eidSGX_, edgeID, indexType_, DOWNLOAD_OPT, 
            //     recvBuf.dataBuffer + CHUNK_HASH_SIZE,
            //     &outEdge->_resOutSGX.sgxClient);
            // TODO: Ecall_Init_Client

            thTmp = new boost::thread(attrs, boost::bind(&EnclaveRecvDecoder::Run, recvDecoderObj_,
                outEdge));
            thList.push_back(thTmp);

            // send the restore-response to the client (include the file recipe header)
            recvBuf.header->messageType = CLOUD_LOGIN_RESPONSE;
            outEdge->_recipeReadHandler.read((char*)recvBuf.dataBuffer,
                sizeof(FileRecipeHead_t));
            if (!dataSecureChannel_->SendData(edgeSSL, recvBuf.sendBuffer, 
                sizeof(NetworkHead_t) + sizeof(FileRecipeHead_t))) {
                tool::Logging(myName_.c_str(), "send the restore-login response error.\n");
                exit(EXIT_FAILURE);
            }
            break;
        }
        default: {
            tool::Logging(myName_.c_str(), "wrong operation type from client: %u\n",
                edgeID);
            exit(EXIT_FAILURE);
        }
    }

    struct timeval sTime;
    struct timeval eTime;
    double totalTime = 0;
    gettimeofday(&sTime, NULL);
    for (auto it : thList) {
        it->join();
    }
    gettimeofday(&eTime, NULL);
    totalTime += tool::GetTimeDiff(sTime, eTime);
    
    // clean up
    for (auto it : thList) {
        delete it;
    }
    thList.clear();
    
    // clean up client variables 
    // TODO: Ecall_Destroy_Client
    switch (optType) {
        case UPLOAD_OPT: {
            // Ecall_Destroy_Client(eidSGX_, outEdge->_upOutSGX.sgxClient);
            break;
        }
        case DOWNLOAD_OPT: {
            // Ecall_Destroy_Client(eidSGX_, outEdge->_resOutSGX.sgxClient);
            break;
        }
        default: {
            tool::Logging(myName_.c_str(), "wrong opt type.\n");
            exit(EXIT_FAILURE);
        }
    }

    // print the info
    double speed = static_cast<double>(outEdge->_uploadDataSize) / 1024.0 / 1024.0 
        / cloudInfo.enclaveProcessTime;
    if (optType == UPLOAD_OPT) { 
        logFile_ << cloudInfo.logicalDataSize << ", " 
            << cloudInfo.logicalChunkNum << ", "
            << cloudInfo.uniqueDataSize << ", " 
            << cloudInfo.uniqueChunkNum << ", "
            << cloudInfo.compressedSize << ", " 
            << to_string(cloudInfo.enclaveProcessTime) << ", "
            << to_string(speed) << endl;
        logFile_.flush();
    }
    delete outEdge; 
    free(recvBuf.sendBuffer);
    tmpLock->unlock();

    tool::Logging(myName_.c_str(), "total running time of edge %u: %lf\n", 
        edgeID, totalTime);

    return ;
}

/**
 * @brief check the file status
 * 
 * @param fullRecipePath the full recipe path
 * @param optType the operation type
 * @return true success
 * @return false fail
 */
bool CloudOptThread::CheckFileStatus(string& fullRecipePath, int optType) {
    if (tool::FileExist(fullRecipePath)) {
        // the file exists
        switch (optType) {
            case UPLOAD_OPT: {
                tool::Logging(myName_.c_str(), "%s exists, overwrite it.\n",
                    fullRecipePath.c_str());
                break;
            }
            case DOWNLOAD_OPT: {
                tool::Logging(myName_.c_str(), "%s exists, access it.\n",
                    fullRecipePath.c_str());
                break;
            }
        }
    } else {
        switch (optType) {
            case UPLOAD_OPT: {
                tool::Logging(myName_.c_str(), "%s not exists, create it.\n",
                    fullRecipePath.c_str());
                break;
            }
            case DOWNLOAD_OPT: {
                tool::Logging(myName_.c_str(), "%s not exists, restore reject.\n",
                    fullRecipePath.c_str());
                return false;
            }
        }
    }
    return true;
}