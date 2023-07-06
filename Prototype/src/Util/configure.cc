/**
 * @file configure.cc
 * @author Zuoru YANG (zryang@cse.cuhk.edu.hk)
 * @brief implement interfaces defined in configure 
 * @version 0.1
 * @date 2019-12-19
 * 
 * @copyright Copyright (c) 2019
 * 
 */
#include "../../include/configure.h"

/**
 * @brief Destroy the Configure:: Configure object
 * 
 */
Configure::~Configure() {
}

/**
 * @brief Construct a new Configure:: Configure object
 * 
 * @param path the configure file path
 */
Configure::Configure(std::string path) {
    this->ReadConf(path);
}

/**
 * @brief read the configure file
 * 
 * @param path the configure file name
 */
void Configure::ReadConf(std::string path) {
    using namespace boost;
    using namespace boost::property_tree;
    ptree root;
    read_json<ptree>(path, root);
    // Chunker configure
    chunkingType_ = root.get<uint64_t>("ChunkerConfig.chunkingType_");
    maxChunkSize_ = root.get<uint64_t>("ChunkerConfig.maxChunkSize_");
    minChunkSize_ = root.get<uint64_t>("ChunkerConfig.minChunkSize_");
    avgChunkSize_ = root.get<uint64_t>("ChunkerConfig.avgChunkSize_");
    slidingWinSize_ = root.get<uint64_t>("ChunkerConfig.slidingWinSize_");
    readSize_ = root.get<uint64_t>("ChunkerConfig.readSize_");

    // StorageCore configure
    recipeRootPath_ = root.get<std::string>("StorageCore.recipeRootPath_");
    upRecipeRootPath_ = root.get<std::string>("StorageCore.upRecipeRootPath_");
    containerRootPath_ = root.get<std::string>("StorageCore.containerRootPath_");
    fp2ChunkDBName_ = root.get<std::string>("StorageCore.fp2ChunkDBName_");
    topKParam_ = root.get<uint64_t>("StorageCore.topKParam_");

    // restore writer
    readCacheSize_ = root.get<uint64_t>("RestoreWriter.readCacheSize_");

    // for storage server 
    storageServerIp_ = root.get<std::string>("DataSender.storageServerIp_");
    storageServerPort_ = root.get<int>("DataSender.storageServerPort_");

    // for client id
    clientID_ = root.get<uint32_t>("DataSender.clientID_");
    sendChunkBatchSize_ = root.get<uint64_t>("DataSender.sendChunkBatchSize_");
    sendRecipeBatchSize_ = root.get<uint64_t>("DataSender.sendRecipeBatchSize_");
    spid_ = root.get<std::string>("DataSender.spid_");
    quoteType_ = root.get<uint16_t>("DataSender.quoteType_");
    iasServerType_ = root.get<uint32_t>("DataSender.iasServerType_");
    iasPrimaryKey_ = root.get<std::string>("DataSender.iasPrimaryKey_");
    iasSecKey_ = root.get<std::string>("DataSender.iasSecKey_");
    iasVersion_ = root.get<uint16_t>("DataSender.iasVersion_");

    // for local secret
    localSecret_ = root.get<string>("DataSender.localSecret_");

    return ;
}