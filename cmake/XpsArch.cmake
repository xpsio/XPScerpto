# cmake/XpsArch.cmake
# Robust per-arch compiler flags as proper CMake LISTs (no quoted blobs).
# Safe defaults: baseline x86-64 (SSE2 only) and ARMv8-A without +crypto unless requested.

include(CheckCXXCompilerFlag)

# ------------------------ Options ------------------------
option(XPS_FORCE_BASELINE                  "Force baseline ISA (portable on all CPUs)"                ON)
option(XPS_ENABLE_AVX2                     "Allow AVX2 for isolated TUs (you must runtime-dispatch)" OFF)
option(XPS_ENABLE_ARM_CRYPTO               "Use +crypto on ARMv8 if supported by compiler/CPU"        OFF)
option(XPS_DISABLE_VECTORIZATION_FOR_TESTS "Disable auto-vectorization on test targets"               ON)
option(XPS_VERBOSE_ARCH_FLAGS              "Print effective arch flags for each target"               ON)

# You may choose a higher baseline on modern fleets (v2/v3), but v1 is safest.
set(XPS_X86_BASELINE "x86-64" CACHE STRING "x86 baseline (x86-64, x86-64-v2, x86-64-v3)")

# ------------------------ Helpers ------------------------
# Append FLAG to OUT_LIST if the compiler accepts it. OUT_LIST is a *CMake list*.
function(xps_check_add_flag OUT_LIST FLAG)
  string(MAKE_C_IDENTIFIER "${FLAG}" _key)
  set(_var "HAVE_${_key}")
  check_cxx_compiler_flag("${FLAG}" ${_var})
  if(${_var})
    set(_tmp "${${OUT_LIST}}")
    list(APPEND _tmp "${FLAG}")
    set(${OUT_LIST} "${_tmp}" PARENT_SCOPE)
  endif()
endfunction()

# Detect coarse host architecture.
function(xps_host_arch OUT)
  string(TOLOWER "${CMAKE_SYSTEM_PROCESSOR}" _proc)
  if(_proc MATCHES "aarch64|arm64")
    set(${OUT} "arm64" PARENT_SCOPE)
  elseif(_proc MATCHES "x86_64|amd64|x86-64")
    set(${OUT} "x86_64" PARENT_SCOPE)
  else()
    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
      set(${OUT} "x86_64" PARENT_SCOPE)
    else()
      set(${OUT} "" PARENT_SCOPE)
    endif()
  endif()
endfunction()

# Join a LIST into a human-readable string (space-separated).
function(xps_flags_to_string IN_LIST OUT_STR)
  set(_L "${IN_LIST}")
  string(REPLACE ";" " " _s "${_L}")
  set(${OUT_STR} "${_s}" PARENT_SCOPE)
endfunction()

# Build a *LIST* of safe ISA flags for the given KIND: "LIB" or "TEST".
function(xps_collect_arch_flags OUT_LIST KIND)
  xps_host_arch(_arch)
  set(_cxxflags)

  if(_arch STREQUAL "x86_64")
    if(XPS_FORCE_BASELINE)
      xps_check_add_flag(_cxxflags "-march=${XPS_X86_BASELINE}")
      xps_check_add_flag(_cxxflags "-mtune=generic")
      # Avoid inadvertent AVX usage on old CPUs/VMs
      xps_check_add_flag(_cxxflags "-mno-avx")
      xps_check_add_flag(_cxxflags "-mno-avx2")
      xps_check_add_flag(_cxxflags "-mno-avx512f")
    endif()
    # NOTE: Do NOT add -mavx2 globally. If you enable AVX2, compile those
    #       TUs separately and guard with runtime CPUID checks.

  elseif(_arch STREQUAL "arm64")
    # On AppleClang, -march flags can be problematic; rely on default target.
    if(APPLE AND CMAKE_CXX_COMPILER_ID MATCHES "AppleClang")
      # no-op
    else()
      xps_check_add_flag(_cxxflags "-march=armv8-a")
      if(XPS_ENABLE_ARM_CRYPTO)
        xps_check_add_flag(_cxxflags "-march=armv8-a+crypto")
      endif()
    endif()
  endif()

  # For tests, make results stable and avoid surprises from auto-vectorizer.
  if(KIND STREQUAL "TEST" AND XPS_DISABLE_VECTORIZATION_FOR_TESTS)
    if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
      xps_check_add_flag(_cxxflags "-fno-tree-vectorize")
    endif()
    # MSVC has no direct global switch; keep default there.
  endif()

  set(${OUT_LIST} "${_cxxflags}" PARENT_SCOPE)
endfunction()

# Apply flags to a target. KIND = "LIB" or "TEST".
function(xps_apply_arch_flags TARGET KIND)
  if(NOT TARGET ${TARGET})
    message(FATAL_ERROR "xps_apply_arch_flags: target '${TARGET}' does not exist")
  endif()

  xps_collect_arch_flags(_flags "${KIND}")
  if(_flags)
    # _flags is already a proper LIST.
    target_compile_options(${TARGET} PRIVATE ${_flags})
  endif()

  if(XPS_VERBOSE_ARCH_FLAGS)
    xps_host_arch(_arch)
    xps_flags_to_string("${_flags}" _s)
    message(STATUS "xps_apply_arch_flags(${TARGET}, ${KIND}) → ${_arch}  CXXFLAGS='${_s}'")
  endif()
endfunction()

