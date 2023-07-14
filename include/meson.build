version_data = configuration_data()
version_data.set('dpservice_version', meson.project_version())
version_h = configure_file(
  input: 'dp_version.h.in',
  output: 'dp_version.h',
  configuration: version_data
)
