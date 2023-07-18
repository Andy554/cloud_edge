# 进行了一系列的配置和设置，包括查找和包含外部库、设置链接目录、设置库对象等。
# 然后使用 add_subdirectory 添加了一些子目录进行构建，每个子目录可能包含不同的源代码和构建规则。
# 这样可以实现分模块的构建和管理，方便地将不同部分的代码组织在一起并进行编译。

find_package(SGX REQUIRED)
find_package(Boost 1.36.0 REQUIRED COMPONENTS thread system serialization)
find_package(LevelDB REQUIRED)
find_package(OpenSSL REQUIRED)
set(SGX_SIM_LIB_PATH /opt/intel/sgxsdk/lib64) # 设置 SGX 模拟库的路径

# 指定 SGX 开发中，通常有一些必须链接的库
if(NOT SGX_HW) # 定义于 Prototype/CMakeLists.txt
    message(STATUS "Using Simulation Mode, SGX_HW: ${SGX_HW}")
    link_directories(${SGX_SIM_LIB_PATH})
    set(SGX_UNTRUST_MUST_LINK sgx_urts_sim sgx_uae_service_sim sgx_capable)
else() 
    set(SGX_UNTRUST_MUST_LINK sgx_urts sgx_uae_service sgx_capable)
endif()

if(Boost_FOUND) # find_package() 返回值
    include_directories(${Boost_INCLUDE_DIRS}) # 指定编译器在编译时查找头文件的目录
    link_directories(${Boost_LIBRARY_DIRS}) # 指定链接器在链接时查找库文件的目录
else()
    message(FATAL_ERROR "Cannot find boost library")
endif()

# TODO 条件编译 RocksDB
if(LevelDB_FOUND)
    include_directories(${LevelDB_INCLUDES})
    link_directories(${LevelDB_LIBRARIES})
else()
    message(FATAL_ERROR "Cannot find Leveldb library")
endif()
message(STATUS "Find LevelDB version: ${LEVELDB_VERSION}")

if(OPENSSL_FOUND) # 已通过其他方式包含和链接 OpenSSL 库？
    # include_directories(${OPENSSL_INCLUDE_DIR})
    # link_directories(${OPENSSL_LIBRARIES})
else()
    message(FATAL_ERROR "Cannot find OpenSSL library")
endif()

message(STATUS "Find OpenSSL version: ${OPENSSL_VERSION}")
if(OPENSSL_VERSION VERSION_LESS "1.1")
    message(FATAL_ERROR "OpenSSL version is less than 1.1")
endif()

set(SGX_INCLUDE_PATH /opt/intel/sgxsdk/include)
include_directories(../include ../build/src/Enclave ${SGX_INCLUDE_PATH})
link_directories(../lib)

set(BOOST_LIBRARY_OBJ boost_thread boost_system boost_serialization)
if(${CMAKE_BUILD_TYPE} STREQUAL "Release")
    set(SYSTEM_LIBRARY_OBJ pthread jemalloc)
else()
    set(SYSTEM_LIBRARY_OBJ pthread)
endif()
set(OPENSSL_LIBRARY_OBJ ssl crypto)
set(THIRD_OBJ ${OPENSSL_LIBRARY_OBJ} leveldb ${BOOST_LIBRARY_OBJ} ${SYSTEM_LIBRARY_OBJ})
set(INSIDE_OBJ UtilCore DatabaseCore IndexCore CommCore IASCore ClientCore ServerCore CloudCore)
set(FINAL_OBJ ${THIRD_OBJ} EnclaveCore ${INSIDE_OBJ})

# 添加子目录进行构建
add_subdirectory(App)
add_subdirectory(Client)
add_subdirectory(Util)
add_subdirectory(Database)
add_subdirectory(Server)
add_subdirectory(Cloud)
add_subdirectory(Enclave)
add_subdirectory(Index)
add_subdirectory(Comm)
add_subdirectory(IASUtil)