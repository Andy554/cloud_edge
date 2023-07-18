aux_source_directory(. CLOUD_SRC)
add_library(CloudCore ${CLOUD_SRC})
# target_link_libraries(CloudCore EnclaveCore IndexCore)
target_link_libraries(CloudCore IndexCore)