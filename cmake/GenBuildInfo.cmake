# GenBuildInfo.cmake — generate a C++ module with build metadata
# Inputs (via -D from add_custom_target):
#   Required:
#     INPUT_TEMPLATE, OUTPUT_FILE
#     XPS_BUILD_NAME
#     XPS_BUILD_MAJOR, XPS_BUILD_MINOR, XPS_BUILD_PATCH
#     XPS_BUILD_API_VERSION, XPS_BUILD_ABI_VERSION
#     (Optional if not passed, we compute reasonable defaults)
#     XPS_BUILD_VERSION_STRING
#     XPS_TOOLCHAIN_* , XPS_SYSTEM_* , XPS_OPT_ENABLE_*_BOOL

# ---- Validate required args ---------------------------------------------------
foreach(_req INPUT_TEMPLATE OUTPUT_FILE XPS_BUILD_NAME
             XPS_BUILD_MAJOR XPS_BUILD_MINOR XPS_BUILD_PATCH
             XPS_BUILD_API_VERSION XPS_BUILD_ABI_VERSION)
  if(NOT DEFINED ${_req})
    message(FATAL_ERROR "GenBuildInfo.cmake: missing required variable: ${_req}")
  endif()
endforeach()

# ---- Ensure output directory exists ------------------------------------------
get_filename_component(_out_dir "${OUTPUT_FILE}" DIRECTORY)
if(_out_dir AND NOT IS_DIRECTORY "${_out_dir}")
  file(MAKE_DIRECTORY "${_out_dir}")
endif()

# ---- Reproducible timestamp (respects SOURCE_DATE_EPOCH) ----------------------
if(DEFINED ENV{SOURCE_DATE_EPOCH})
  set(_epoch $ENV{SOURCE_DATE_EPOCH})
  string(TIMESTAMP XPS_BUILD_DATE "%Y-%m-%d" UTC ${_epoch})
  string(TIMESTAMP XPS_BUILD_TIME "%H:%M:%S" UTC ${_epoch})
else()
  string(TIMESTAMP XPS_BUILD_DATE "%Y-%m-%d" UTC)
  string(TIMESTAMP XPS_BUILD_TIME "%H:%M:%S" UTC)
endif()

# ---- VCS info (git if available) ---------------------------------------------
set(XPS_VCS "none")
set(XPS_GIT_COMMIT "")
set(XPS_GIT_BRANCH "")
set(XPS_GIT_DESCRIBE "")
set(XPS_GIT_DIRTY_BOOL false)

find_program(_GIT git)
if(_GIT)
  execute_process(COMMAND "${_GIT}" rev-parse --short=12 HEAD
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
    OUTPUT_VARIABLE _commit OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET)
  if(_commit)
    set(XPS_VCS "git")
    set(XPS_GIT_COMMIT "${_commit}")

    execute_process(COMMAND "${_GIT}" rev-parse --abbrev-ref HEAD
      WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
      OUTPUT_VARIABLE _branch OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET)
    # detached HEAD returns "HEAD" — نعتمدها كما هي
    set(XPS_GIT_BRANCH "${_branch}")

    execute_process(COMMAND "${_GIT}" describe --tags --dirty --always
      WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
      OUTPUT_VARIABLE _desc OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET)
    set(XPS_GIT_DESCRIBE "${_desc}")

    # dirty (1 = dirty, 0 = clean, 128 = no repo/other)
    execute_process(COMMAND "${_GIT}" diff --quiet --ignore-submodules HEAD
      WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
      RESULT_VARIABLE _dirty_rc ERROR_QUIET)
    if(_dirty_rc EQUAL 1)
      set(XPS_GIT_DIRTY_BOOL true)
    endif()
  endif()
endif()

# ---- Compose VERSION_STRING if not provided -----------------------------------
if(NOT DEFINED XPS_BUILD_VERSION_STRING OR XPS_BUILD_VERSION_STRING STREQUAL "")
  if(XPS_GIT_DESCRIBE)
    set(XPS_BUILD_VERSION_STRING
        "${XPS_BUILD_MAJOR}.${XPS_BUILD_MINOR}.${XPS_BUILD_PATCH} (${XPS_GIT_DESCRIBE})")
  else()
    set(XPS_BUILD_VERSION_STRING
        "${XPS_BUILD_MAJOR}.${XPS_BUILD_MINOR}.${XPS_BUILD_PATCH}")
  endif()
endif()

# ---- Normalize booleans to literal true/false for @ONLY -----------------------
foreach(_b XPS_OPT_ENABLE_AVX2_BOOL XPS_OPT_ENABLE_NEON_BOOL XPS_GIT_DIRTY_BOOL)
  if(NOT DEFINED ${_b})
    set(${_b} false)
  endif()
  if(${_b})
    set(${_b} true)
  else()
    set(${_b} false)
  endif()
endforeach()

# ---- Escape strings that may contain quotes/backslashes -----------------------
foreach(VAR
  XPS_BUILD_NAME XPS_BUILD_VERSION_STRING
  XPS_TOOLCHAIN_COMPILER_ID XPS_TOOLCHAIN_COMPILER_VERSION XPS_TOOLCHAIN_STDLIB
  XPS_TOOLCHAIN_GENERATOR XPS_CMAKE_VERSION
  XPS_SYSTEM_NAME XPS_SYSTEM_PROCESSOR
  XPS_GIT_COMMIT XPS_GIT_BRANCH XPS_GIT_DESCRIBE XPS_VCS
  XPS_BUILD_DATE XPS_BUILD_TIME
)
  if(DEFINED ${VAR})
    string(REPLACE "\\" "\\\\" ${VAR} "${${VAR}}")
    string(REPLACE "\"" "\\\""  ${VAR} "${${VAR}}")
  endif()
endforeach()

# ---- Generate file from template ---------------------------------------------
configure_file("${INPUT_TEMPLATE}" "${OUTPUT_FILE}" @ONLY)

