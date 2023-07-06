#include "configure.h"
#include "sslConnection.h"
#include "messageQueue.h"
#include "cryptoPrimitive.h"

extern Configure config;

class Uploader {
    private:
        string myName_ = "uploader";
        SSLConnection* dataSecureChannel_;
        pair<int, SSL*> conChannelRecord_;
        
        // config
        uint64_t sendChunkBatchSize_ = 0;
        uint64_t sendRecipeBatchSize_ = 0;
        uint32_t edgeID_;

        // for security channel encryption
        CryptoPrimitive* cryptoObj_;
        uint8_t sessionKey_[CHUNK_HASH_SIZE];
        EVP_CIPHER_CTX* cipherCtx_;
        EVP_MD_CTX* mdCtx_;

        uint64_t batchNum_ = 0;
        
        // the sender buffer 
        SendMsgBuffer_t sendChunkBuf_;
        SendMsgBuffer_t sendFpBuf_;
        SendMsgBuffer_t sendEncBuffer_;
        MessageQueue<Data_t>* inputMQ_;

        double totalTime_ = 0;

        void InsertChunkToSenderBuffer(Chunk_t& inputChunk);

        void SendCurrentSegment();

        void SendRecipeEnd(Data_t& recipeHead);

        void ProcessRecipeEnd(FileRecipeHead_t& recipeHead);

        void ProcessChunk(Chunk_t& inputChunk);

        void ProcessFp(uint8_t* fp);

        void ProcessFpEnd();

        void SendChunks();

        void SendFps();

    public:
        Uploader(SSLConnection* dataSecureChannel);


        ~Uploader();


        void Run();


        void UploadLogin(string localSecret, uint8_t* fileNameHash);
        

        void SetConnectionRecord(pair<int, SSL*> conChannelRecord) {
            conChannelRecord_ = conChannelRecord;
            return ;
        }


        void SetSessionKey(uint8_t* sessionKey, size_t keySize) {
            memcpy(sessionKey_, sessionKey, keySize);
            return ;
        }

        void SetInputMQ(MessageQueue<Data_t>* inputMQ) {
            inputMQ_ = inputMQ;
            return ;
        }
};
