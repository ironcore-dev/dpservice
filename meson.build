project('dp_service', 'c', 'cpp',
  version: run_command('git', 'describe', '--tags').stdout().strip(),
  license: 'MIT',
  default_options: ['warning_level=2', 'werror=true'])

# RTE uses deprecation for experimental API
cflags = ['-Wno-deprecated-declarations']
cxxflags = []

# Customize compiler warnings (unless warning_level is changed to a lower value)
if get_option('warning_level').to_int() >= 2
  common_flags = [
    # -Werror provided by 'werror=true' in default project options
    # -Wall -Wextra provided by 'warning_level=2' in default project options
     '-Wunused', '-Wshadow', '-Wundef', '-Wcast-qual', '-Wwrite-strings', '-Wpointer-arith',
  ]
  cflags += common_flags + [
    '-Wbad-function-cast', '-Wmissing-declarations', '-Wstrict-prototypes', '-Wmissing-prototypes',
  ]
  cxxflags += common_flags + [
    '-Wno-missing-field-initializers',
  ]
  if meson.get_compiler('c').get_id() == 'clang'
    cflags += [
      '-Wshadow-all', '-Wparentheses', '-Wcomma', '-Warray-bounds-pointer-arithmetic',
      '-Wunreachable-code', '-Wunreachable-code-break', '-Wextra-semi-stmt', '-Wmissing-variable-declarations',
      '-Wuninitialized', '-Wconditional-uninitialized',
      '-Wassign-enum', '-Wduplicate-enum',
      '-Wused-but-marked-unused',
    ]
  else  # Assume GCC
    cflags += [
      '-Wstringop-overflow=4',
    ]
    # Additional warnings to suggest better code, GCC only (as that is the primary builder)
    if get_option('compiler_suggestions')
      cflags += [
        '-Winline', '-Wno-error=inline',
        '-Wsuggest-attribute=noreturn', '-Wsuggest-attribute=malloc',
        # These suggestions are not usable right now, but could be nice: const, pure, cold
      ]
    endif
  endif
endif
add_project_arguments(cflags, language : 'c')
add_project_arguments(cxxflags, language : 'cpp')

add_global_arguments('-DDEBUG=true', language: ['c', 'cpp'])
if get_option('enable_virtual_services')
  add_global_arguments('-DENABLE_VIRTSVC', language: ['c', 'cpp'])
endif
if get_option('enable_static_underlay_ip')
  add_global_arguments('-DENABLE_STATIC_UNDERLAY_IP', language: 'c')
endif

dpdk_dep = dependency('libdpdk', version: '>=21.11.0')
proto_dep = dependency('protobuf')
grpc_dep = dependency('grpc')
grpccpp_dep = dependency('grpc++')
thread_dep = dependency('threads')
libuuid_dep = dependency('uuid')

protoc = find_program('protoc')
grpc_cpp = find_program('grpc_cpp_plugin')
if get_option('enable_tests')
  pytest = find_program('pytest', 'pytest-3')
  scapy = find_program('scapy')
  add_global_arguments('-DENABLE_PYTEST', language: 'c')
endif
if get_option('enable_usermode')
  sudo = find_program('sudo')
  setcap = find_program('setcap', '/usr/sbin/setcap')
endif

includes = include_directories('include')

subdir('proto')
subdir('include')
subdir('src')
subdir('tools')
if get_option('enable_tests')
  subdir('test')
endif

cppcheck = find_program('cppcheck', required: false)
if cppcheck.found()
  run_target('cppcheck', command: [cppcheck, '--project=' +
    join_paths(meson.build_root(), 'compile_commands.json')])
endif
