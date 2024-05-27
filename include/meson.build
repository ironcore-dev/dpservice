version_data = configuration_data()
version_data.set('dpservice_version', meson.project_version())
version_h = configure_file(
  input: 'dp_version.h.in',
  output: 'dp_version.h',
  configuration: version_data,
)
# This should be working in itself, but for some reason, dump/ directory gets built *before* this,
# therefore the above configure phase ensures a valid version.h
version_h = vcs_tag(
  command: ['git', 'describe', '--tags'],
  input: 'dp_version.h.in',
  output: 'dp_version.h',
  replace_string: '@dpservice_version@'
)
