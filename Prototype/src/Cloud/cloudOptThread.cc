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

#include "../../include/cloudOptThead.h"

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
    absIndexObj_ = new EnclaveIndex(fp2ChunkDB_, indexType_, eidSGX_);
    absIndexObj_->SetStorageCoreObj(storageCoreObj_);
    dataReceiverObj_ = new DataReceiver(absIndexObj_, dataSecureChannel_, eidSGX_);
    dataReceiverObj_->SetStorageCoreObj(storageCoreObj_);
    //uploaderObj_ = new Uploader();


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
        logFile_ << "indeduptime  " << "outdeduptime  "
            << "sftime  " << "indelta  "
            << "outdelta  " << "conI_Otime  "
            << "conupdate  " << "process  " << "deltaprocess  " << "uniqueprocess  " << "backup_unique  " << "backup_delta  " << "backup_indelta  " << "backup_outdelta  " << "backup_delay_pop  " << "backup_delay_push  " <<"backup_total  "<<"backup_encalve_total  "  << endl;
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

    fprintf(stderr, "========CloudOptThread Info========\n");
    fprintf(stderr, "total recv upload requests: %lu\n", totalUploadReqNum_);
    fprintf(stderr, "total recv download requests: %lu\n", totalRestoreReqNum_);
    fprintf(stderr, "====================================\n");
}

/**
 * @brief the main process
 * 
 * @param clientSSL the client ssl
 */
void CloudOptThread::Run(SSL* clientSSL) {
    boost::thread* thTmp;
    boost::thread_attributes attrs;
    attrs.set_stack_size(THREAD_STACK_SIZE);
    vector<boost::thread*> thList;
    EnclaveInfo_t enclaveInfo;

    SendMsgBuffer_t recvBuf;
    recvBuf.sendBuffer = (uint8_t*) malloc(sizeof(NetworkHead_t) + SESSION_KEY_BUFFER_SIZE);
    recvBuf.header = (NetworkHead_t*) recvBuf.sendBuffer;
    recvBuf.header->dataSize = 0;
    recvBuf.dataBuffer = recvBuf.sendBuffer + sizeof(NetworkHead_t);
    uint32_t recvSize = 0;

    tool::Logging(myName_.c_str(), "the main thread is running.\n");

#if (ENABLE_SGX_RA == 1)
    // check whether do remote attestation
    if (!dataSecureChannel_->ReceiveData(clientSSL, recvBuf.sendBuffer, recvSize)) {
        tool::Logging(myName_.c_str(), "recv RA decision fails.\n");
        exit(EXIT_FAILURE);
    }
    sgx_ra_context_t raCtx;
    switch (recvBuf.header->messageType) {
        case SGX_RA_NEED: {
            raUtil_->DoAttestation(eidSGX_, raCtx, clientSSL);
            if (!dataSecureChannel_->ReceiveData(clientSSL, recvBuf.sendBuffer, recvSize)) {
                tool::Logging(myName_.c_str(), "client closed socket connect, RA finish.\n");
                dataSecureChannel_->ClearAcceptedClientSd(clientSSL);
            }
            free(recvBuf.sendBuffer);
            return ;
        }
        case SGX_RA_NOT_NEED: {
            break;
        }
        default: {
            tool::Logging(myName_.c_str(), "wrong RA request type.\n");
            exit(EXIT_FAILURE);
        }
    }

#else
    // wait the RA request
    if (!dataSecureChannel_->ReceiveData(clientSSL, recvBuf.sendBuffer, recvSize)) {
        tool::Logging(myName_.c_str(), "recv the RA request header fails.\n");
        exit(EXIT_FAILURE);
    } 
    switch (recvBuf.header->messageType) {
        case SGX_RA_NOT_SUPPORT: {
            // cannot perform RA
            if (!dataSecureChannel_->ReceiveData(clientSSL, recvBuf.sendBuffer, 
                recvSize)) {
                tool::Logging(myName_.c_str(), "client closed socket connect, RA not support.\n");
                dataSecureChannel_->ClearAcceptedClientSd(clientSSL);
            }
            free(recvBuf.sendBuffer);
            return;
        }
        case SGX_RA_NOT_NEED: {
            // does not need to perform RA
            break;   
        }
        default: {
            tool::Logging(myName_.c_str(), "wrong RA request type.\n");
            exit(EXIT_FAILURE);
        }
    }
#endif

    // generate the session key
    if (!dataSecureChannel_->ReceiveData(clientSSL, recvBuf.sendBuffer, 
        recvSize)) {
        tool::Logging(myName_.c_str(), "recv the session key request error.\n");
        exit(EXIT_FAILURE);
    }
    if (recvBuf.header->messageType != SESSION_KEY_INIT) { 
        tool::Logging(myName_.c_str(), "recv the wrong session key init type.\n");
        exit(EXIT_FAILURE);
    }

    // check the client lock here (ensure exist only one client with the same client ID)
    uint32_t clientID = recvBuf.header->clientID;
    boost::mutex* tmpLock;
    {
        lock_guard<mutex> lock(clientLockSetLock_);
        auto clientLockRes = clientLockIndex_.find(clientID);
        if (clientLockRes != clientLockIndex_.end()) {
            // try to lock this mutex
            tmpLock = clientLockIndex_[clientID];
            tmpLock->lock();
        } else {
            // add a new lock to the current index
            tmpLock = new boost::mutex();
            clientLockIndex_[clientID] = tmpLock;
            tmpLock->lock();
        }
    }

    struct timeval sTime;
    struct timeval eTime;
    double keyExchangeTime = 0;
    gettimeofday(&sTime, NULL);
    Ecall_Session_Key_Exchange(eidSGX_, recvBuf.dataBuffer, clientID);
    gettimeofday(&eTime, NULL);
    keyExchangeTime = tool::GetTimeDiff(sTime, eTime);

    recvBuf.header->messageType = SESSION_KEY_REPLY;
    if (!dataSecureChannel_->SendData(clientSSL, recvBuf.sendBuffer,
        sizeof(NetworkHead_t) + SESSION_KEY_BUFFER_SIZE)) {
        tool::Logging(myName_.c_str(), "send the session key fails.\n");
        exit(EXIT_FAILURE);
    }
    if (!dataSecureChannel_->ReceiveData(clientSSL, recvBuf.sendBuffer, 
        recvSize)) {
        tool::Logging(myName_.c_str(), "recv the login message error.\n");
        exit(EXIT_FAILURE);
    }

    // ---- the main process ----
    int optType = 0;
    switch (recvBuf.header->messageType) {
        case CLIENT_LOGIN_UPLOAD: {
            optType = UPLOAD_OPT;
            break;
        }
        case CLIENT_LOGIN_DOWNLOAD: {
            optType = DOWNLOAD_OPT;
            break;
        }
        default: {
            tool::Logging(myName_.c_str(), "wrong client login type.\n");
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
    string recipePath = config.GetRecipeRootPath() +
        fileName + config.GetRecipeSuffix();
    string upRecipePath = config.GetUpRecipeRootPath() +
        fileName + config.GetRecipeSuffix();
    if (!this->CheckFileStatus(recipePath, optType)) {
        recvBuf.header->messageType = SERVER_FILE_NON_EXIST;
        if (!dataSecureChannel_->SendData(clientSSL, recvBuf.sendBuffer,
            sizeof(NetworkHead_t))) {
            tool::Logging(myName_.c_str(), "send the file not exist reply error.\n");
            exit(EXIT_FAILURE);
        }

        // wait the client to close the connection
        if (!dataSecureChannel_->ReceiveData(clientSSL, 
            recvBuf.sendBuffer, recvSize)) {
            tool::Logging(myName_.c_str(), "client close the socket connection.\n");
            dataSecureChannel_->ClearAcceptedClientSd(clientSSL);
        } else {
            tool::Logging(myName_.c_str(), "client does not close the connection.\n");
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
    
    // init the vars for this client
    ClientVar* outClient;
    switch (optType) {
        case UPLOAD_OPT: {
            // update the req number
            totalUploadReqNum_++;
            tool::Logging(myName_.c_str(), "recv the upload request from client: %u\n",
                clientID);
            outClient = new ClientVar(clientID, clientSSL, UPLOAD_OPT, recipePath, upRecipePath);
            Ecall_Init_Client(eidSGX_, clientID, indexType_, UPLOAD_OPT, 
                recvBuf.dataBuffer + CHUNK_HASH_SIZE, 
                &outClient->_upOutSGX.sgxClient);

            thTmp = new boost::thread(attrs, boost::bind(&DataReceiver::Run, dataReceiverObj_,
                outClient, &enclaveInfo));
            thList.push_back(thTmp); 
#if (MULTI_CLIENT == 0)
            thTmp = new boost::thread(attrs, boost::bind(&DataWriter::Run, dataWriterObj_,
                outClient->_inputMQ));
            thList.push_back(thTmp);
#endif
            // send the upload-response to the client
            recvBuf.header->messageType = SERVER_LOGIN_RESPONSE;
            if (!dataSecureChannel_->SendData(clientSSL, recvBuf.sendBuffer, 
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
                clientID);
            outClient = new ClientVar(clientID, clientSSL, DOWNLOAD_OPT, recipePath, upRecipePath);
            Ecall_Init_Client(eidSGX_, clientID, indexType_, DOWNLOAD_OPT, 
                recvBuf.dataBuffer + CHUNK_HASH_SIZE,
                &outClient->_resOutSGX.sgxClient);

            // 修改了以下两行代码的顺序，本来在thtmp后面
            // send the restore-response to the client (include the file recipe header)
            recvBuf.header->messageType = SERVER_LOGIN_RESPONSE;
            outClient->_recipeReadHandler.read((char*)recvBuf.dataBuffer,
                sizeof(FileRecipeHead_t));
            
            // 检查文件的位置
            char *tmpIsInEdge = (char*)malloc(sizeof(char));
            outClient->_recipeReadHandler.read((char*)tmpIsInEdge,
                sizeof(char));
                
            if(tmpIsInEdge[0] == IN_EDGE) {
                tool::Logging(myName_.c_str(), "file is in edge.\n", tmpIsInEdge);

                thTmp = new boost::thread(attrs, boost::bind(&EnclaveRecvDecoder::Run, recvDecoderObj_,
                    outClient));
                thList.push_back(thTmp);
            }
            else {
                tool::Logging(myName_.c_str(), "file is in cloud.\n", tmpIsInEdge);
                //
            }
            
            if (!dataSecureChannel_->SendData(clientSSL, recvBuf.sendBuffer, 
                sizeof(NetworkHead_t) + sizeof(FileRecipeHead_t))) {
                tool::Logging(myName_.c_str(), "send the restore-login response error.\n");
                exit(EXIT_FAILURE);
            }
            break;
        }
        default: {
            tool::Logging(myName_.c_str(), "wrong operation type from client: %u\n",
                clientID);
            exit(EXIT_FAILURE);
        }
    }

    double totalTime = 0;
    gettimeofday(&sTime, NULL);
    for (auto it : thList) {
        it->join();
    }
    gettimeofday(&eTime, NULL);
    totalTime += tool::GetTimeDiff(sTime, eTime);
    /*
    if(){
        uint32_t edgeID = config.GetClientID();
        
        SSLConnection* dataSecureChannel = new SSLConnection(config.GetStorageCloudIP(), 
        config.GetStoragePort(), IN_CLIENTSIDE);
        pair<int, SSL*> cloudConnectionRecord = dataSecureChannel->ConnectSSL();
        SSL* cloudConnection = cloudConnectionRecord.second;
        
        SessionKeyExchange* sessionKeyObj = new SessionKeyExchange(dataSecureChannel);
        uint8_t sessionKey[CHUNK_HASH_SIZE] = {0};
        sessionKeyObj->GeneratingSecret(sessionKey, cloudConnection, edgeID);
        
        uploaderObj_ = new Uploader(dataSecureChannel);
        uploaderObj_->SetConnectionRecord(cloudConnectionRecord);
        uploaderObj_->SetSessionKey(sessionKey, CHUNK_HASH_SIZE);
        
        string updateFile;
        //TODO：启动一个线程选择上传文件，计算上传指纹
    
        string fullName = updateFile + to_string(edgeID);
        uint8_t fileNameHash[CHUNK_HASH_SIZE] = {0};
        cryptoObj->GenerateHash(mdCtx, (uint8_t*)&fullName[0],
            fullName.size(), fileNameHash);

        MessageQueue<Data_t>* chunker2SenderMQ = new MessageQueue<Data_t>(CHUNK_QUEUE_SIZE);
        uploaderObj_->SetInputMQ(chunker2SenderMQ);
        uploaderObj_->UploadLogin(config.GetLocalSecret(),fileNameHash);
        
        thTmp = new boost::thread(attrs, boost::bind(&Uploader::Run, uploaderObj_));
        thList.push_back(thTmp); 
    }
    */
    // clean up
    for (auto it : thList) {
        delete it;
    }
    thList.clear();
    
    // clean up client variables 
    switch (optType) {
        case UPLOAD_OPT: {
            Ecall_Destroy_Client(eidSGX_, outClient->_upOutSGX.sgxClient);
            break;
        }
        case DOWNLOAD_OPT: {
            Ecall_Destroy_Client(eidSGX_, outClient->_resOutSGX.sgxClient);
            break;
        }
        default: {
            tool::Logging(myName_.c_str(), "wrong opt type.\n");
            exit(EXIT_FAILURE);
        }
    }

    // print the info
    double speed = static_cast<double>(outClient->_uploadDataSize) / 1024.0 / 1024.0 
        / enclaveInfo.enclaveProcessTime;
    if (optType == UPLOAD_OPT) {
         logFile_ << enclaveInfo.indeduptime << ", " 
            << enclaveInfo.outdeduptime << ", "
            << enclaveInfo.sftime << ", " 
            << enclaveInfo.indeltatime << ", "
            << enclaveInfo.outdeltatime << ", " 
            << enclaveInfo.conI_Otime << ", "
            << enclaveInfo.conupdatetime << ", "
            << enclaveInfo.processtime << ", "
            << enclaveInfo.deltaprocesstime << ", "
            << enclaveInfo.uniqueprocesstime << ", "
            << enclaveInfo.backup_unique << ", "
            << enclaveInfo.backup_delta << ", "
            << enclaveInfo.backup_indelta << ", "
            << enclaveInfo.backup_outdelta << ", "
            << enclaveInfo.backup_delay_pop << ", "
            << enclaveInfo.backup_delay_push << ", "
            << enclaveInfo.backup_total << ", "
            << enclaveInfo.backup_enclave_total << ", "<<endl;
        logFile_.flush();

#if (SGX_BREAKDOWN == 1)
        double dataMB = static_cast<double>(outClient->_uploadDataSize) / 1024.0 / 1024.0;
        tool::Logging(myName_.c_str(), "data tran time: %lf\n", 
            (enclaveInfo.dataTranTime + keyExchangeTime * 1000.0) / dataMB);
        tool::Logging(myName_.c_str(), "fingerprint time: %lf\n",
            enclaveInfo.fpTime / dataMB);
        tool::Logging(myName_.c_str(), "freq counting time: %lf\n",
            enclaveInfo.freqTime / dataMB);
        tool::Logging(myName_.c_str(), "first-dedup time: %lf\n",
            enclaveInfo.firstDedupTime / dataMB);
        tool::Logging(myName_.c_str(), "second-dedup time: %lf\n",
            enclaveInfo.secondDedupTime / dataMB);
        tool::Logging(myName_.c_str(), "compression time: %lf\n",
            enclaveInfo.compTime / dataMB);
        tool::Logging(myName_.c_str(), "encryption time: %lf\n",
            enclaveInfo.encTime / dataMB);
#endif
    }
    delete outClient;
    free(recvBuf.sendBuffer);
    tmpLock->unlock();

    tool::Logging(myName_.c_str(), "total running time of client %u: %lf\n", 
        clientID, totalTime);
    tool::Logging(myName_.c_str(), "total key exchange time of client %u: %lf\n", 
        clientID, keyExchangeTime); 

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