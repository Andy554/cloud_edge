# Try to find rocksdb
# Once done, this will define
# source: https://gitlab.cern.ch/dss/eos/blob/master/cmake/FindRocksDB.cmake
#
# ROCKSDB_FOUND              - system has rocksdb
# ROCKSDB_INCLUDE_DIRS       - rocksdb include directories
# ROCKSDB_LIBRARY            - rocksdb library
#
# ROCKSDB_ROOT_DIR may be defined as a hint for where to look

include(FindPackageHandleStandardArgs)

if(ROCKSDB_INCLUDE_DIRS AND ROCKSDB_LIBRARIES)
    set(ROCKSDB_FIND_QUIETLY TRUE)
else()
    find_path(
            ROCKSDB_INCLUDE_DIR
            NAMES rocksdb/version.h
            HINTS  ${ROCKSDB_ROOT_DIR}
            PATH_SUFFIXES include)

    find_library(
            ROCKSDB_LIBRARY
            NAMES librocksdb.a
            HINTS ${ROCKSDB_ROOT_DIR})

    set(ROCKSDB_LIBRARIES ${ROCKSDB_LIBRARY})
    set(ROCKSDB_INCLUDE_DIRS ${ROCKSDB_INCLUDE_DIR})

    find_package_handle_standard_args(
            RocksDB 
            DEFAULT_MSG
            ROCKSDB_LIBRARY
            ROCKSDB_INCLUDE_DIR)

    if(ROCKSDB_FOUND)
        add_library(rocksdb STATIC IMPORTED)
        set_property(TARGET rocksdb PROPERTY IMPORTED_LOCATION ${ROCKSDB_LIBRARY})
    endif()
endif()