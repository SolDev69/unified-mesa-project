files_blake3 = [
    'blake3.c',
    'blake3_dispatch.c',
    'blake3_portable.c'
]
blake3_defs = []

is_windows = host_machine.system() == 'windows'
is_msvc = meson.get_compiler('c').get_id() == 'msvc'
cpu_family = host_machine.cpu_family()

blake3_x86_no_simd_defs = ['-DBLAKE3_NO_SSE2', '-DBLAKE3_NO_SSE41', '-DBLAKE3_NO_AVX2', '-DBLAKE3_NO_AVX512']

if cpu_family == 'x86'
  # There are no assembly versions for 32-bit x86. Compiling the C versions require a different compilation flag per
  # file, which is not well supported by Meson. Leave SIMD support out for now.
  blake3_defs += blake3_x86_no_simd_defs
endif

blake3 = static_library(
  'blake3',
  files_blake3,
  c_args : blake3_defs,
  gnu_symbol_visibility : 'hidden',
)

idep_blake3 = declare_dependency(
  link_with : blake3,
)
