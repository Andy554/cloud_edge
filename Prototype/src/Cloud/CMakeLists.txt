# 失败了
# DataReceiver(AbsIndex* absIndexObj, SSLConnection* dataSecureChannel, sgx_enclave_id_t eidSGX)
# note: candidate constructor not viable: requires 3 arguments, but 2 were provided
set(CLOUD_COMPILE ON CACHE BOOL "Enable cloud side compile")

aux_source_directory(. CLOUD_SRC)
add_library(CloudCore ${CLOUD_SRC})
# target_link_libraries(CloudCore EnclaveCore IndexCore)
target_link_libraries(CloudCore IndexCore)