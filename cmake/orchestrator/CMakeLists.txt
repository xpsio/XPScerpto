# src/modules/orchestrator/CMakeLists.txt

# Requires CMake ≥ 3.28 for first-class C++ modules
if(CMAKE_VERSION VERSION_LESS 3.28)
  message(FATAL_ERROR "CMake 3.28+ is required for C++ Modules in orchestrator/")
endif()

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Threads for std::shared_mutex on POSIX
find_package(Threads REQUIRED)

# ──────────────────────────────────────────────────────────────
# xps.crypto.orchestrator.attest
add_library(xps.crypto.orchestrator.attest)
target_sources(xps.crypto.orchestrator.attest
  PUBLIC
    FILE_SET cxx_modules TYPE CXX_MODULES
    FILES
      ${CMAKE_CURRENT_SOURCE_DIR}/xps.crypto.orchestrator.attest.ixx
)
target_link_libraries(xps.crypto.orchestrator.attest
  PUBLIC
    Threads::Threads
)
target_compile_features(xps.crypto.orchestrator.attest PUBLIC cxx_std_23)

# ──────────────────────────────────────────────────────────────
# xps.crypto.orchestrator.planner
add_library(xps.crypto.orchestrator.planner)
target_sources(xps.crypto.orchestrator.planner
  PUBLIC
    FILE_SET cxx_modules TYPE CXX_MODULES
    FILES
      ${CMAKE_CURRENT_SOURCE_DIR}/xps.crypto.orchestrator.planner.ixx
)
target_link_libraries(xps.crypto.orchestrator.planner
  PUBLIC
    xps.crypto.simd.hybrid
    xps.crypto.orchestrator.attest
    Threads::Threads
)
target_compile_features(xps.crypto.orchestrator.planner PUBLIC cxx_std_23)

# ──────────────────────────────────────────────────────────────
# xps.crypto.orchestrator.guard
add_library(xps.crypto.orchestrator.guard)
target_sources(xps.crypto.orchestrator.guard
  PUBLIC
    FILE_SET cxx_modules TYPE CXX_MODULES
    FILES
      ${CMAKE_CURRENT_SOURCE_DIR}/xps.crypto.orchestrator.guard.ixx
)
target_link_libraries(xps.crypto.orchestrator.guard
  PUBLIC
    xps.crypto.orchestrator.planner
    xps.crypto.simd.hybrid
    Threads::Threads
)
target_compile_features(xps.crypto.orchestrator.guard PUBLIC cxx_std_23)

# ──────────────────────────────────────────────────────────────
# xps.crypto.orchestrator.bind
add_library(xps.crypto.orchestrator.bind)
target_sources(xps.crypto.orchestrator.bind
  PUBLIC
    FILE_SET cxx_modules TYPE CXX_MODULES
    FILES
      ${CMAKE_CURRENT_SOURCE_DIR}/xps.crypto.orchestrator.bind.ixx
)
target_link_libraries(xps.crypto.orchestrator.bind
  PUBLIC
    xps.crypto.simd.hybrid
    Threads::Threads
)
target_compile_features(xps.crypto.orchestrator.bind PUBLIC cxx_std_23)

