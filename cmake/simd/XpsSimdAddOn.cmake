
# XpsSimdAddOn.cmake — minimal integration helpers

function(xps_enable_constant_time target)
  # Conservative flags for CT-critical code paths (tweak per target as needed)
  target_compile_options(${target} PRIVATE
    -fno-builtin -fno-strict-aliasing -fno-tree-vectorize
  )
endfunction()

function(xps_disable_avx512 target)
  # Helps mitigate downclock on some CPUs if you decide to avoid AVX-512 for a target
  target_compile_options(${target} PRIVATE -mno-avx512f -mno-avx512vl -mno-avx512bw -mno-avx512dq)
endfunction()

# Example:
# add_library(xps_simd_addon
#   src/modules/xps.crypto.policy.ixx
#   src/modules/xps.crypto.simd.calibrate.ixx
#   src/modules/xps.crypto.simd.fastpath.ixx)
# target_sources(xps_simd_addon PUBLIC
#   FILE_SET CXX_MODULES FILES
#     src/modules/xps.crypto.policy.ixx
#     src/modules/xps.crypto.simd.calibrate.ixx
#     src/modules/xps.crypto.simd.fastpath.ixx)
# target_include_directories(xps_simd_addon PUBLIC ${CMAKE_CURRENT_LIST_DIR}/../include)
