make = find_program('make')
find_program('go')

custom_target('dpservice-cli',
  output: 'dpservice-cli',
  command: [ make, '-s', '-C', '@CURRENT_SOURCE_DIR@', 'meson', 'MESON_OUTPUT='+meson.build_root()/'@OUTPUT@' ],
  build_by_default: true,
  build_always_stale: true,
)
