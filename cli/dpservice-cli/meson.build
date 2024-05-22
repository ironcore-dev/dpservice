if get_option('build_dpservice_cli')
  custom_target('build_and_copy_dpservice_cli',
    output: 'dpservice-cli',
    command: [meson.source_root() / 'cli' / 'dpservice-cli' / 'build_dpservice_cli.sh'],
    build_by_default: true
  )
endif
