#include "sgx_urts.h"
#include "sgx_capable.h"
#include "../build/src/Enclave/storeEnclave_u.h"
#include "configure.h"
#include "cryptoPrimitive.h"
#include "readCache.h"
#include "absDatabase.h"
#include "sslConnection.h"
#include "absRecvDecoder.h"
#include "clientVar.h"

extern Configure config;

class EdgeChunker : public AbsRecvDecoder {
    private:
        string myName_ = "EdgeChunker";
        // the variable to record the enclave information 
        sgx_enclave_id_t eidSGX_;

        bool* isInCloud;
    public:
        /**
         * @brief Construct a new EnclaveRecvDecoder object
         * 
         * @param dataSecureChannel the ssl connection pointer
         * @param eidSGX the id to the enclave
         */
        EdgeChunker(SSLConnection* dataSecureChannel, 
            sgx_enclave_id_t eidSGX);

        /**
         * @brief Destroy the Enclave Recv Decoder object
         * 
         */
        ~EdgeChunker();

        /**
         * @brief the main process
         * 
         * @param outClient the out-enclave client ptr
         */
        void Run(ClientVar* outClient);
};
