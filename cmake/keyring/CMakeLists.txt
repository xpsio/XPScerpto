# src/modules/keyring/CMakeLists.txt

if(CMAKE_VERSION VERSION_LESS 3.28)
  message(FATAL_ERROR "CMake 3.28+ is required for C++ Modules in keyring/")
endif()

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(xps.crypto.keyring.policy)
target_sources(xps.crypto.keyring.policy
  PUBLIC
    FILE_SET cxx_modules TYPE CXX_MODULES
    FILES
      ${CMAKE_CURRENT_SOURCE_DIR}/xps.crypto.keyring.policy.ixx
)
target_compile_features(xps.crypto.keyring.policy PUBLIC cxx_std_23)

if(TARGET xps.crypto.simd.dispatch.types)
  target_link_libraries(xps.crypto.keyring.policy PUBLIC xps.crypto.simd.dispatch.types)
endif()

