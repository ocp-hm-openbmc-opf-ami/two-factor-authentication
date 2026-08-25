project('WebTwoFactorAuthentication',
  'cpp',
  version: '1.0',
  meson_version: '>=0.58.0',
  default_options: [
    'werror=true',
    'warning_level=3',
    'cpp_std=c++20',
    'buildtype=debugoptimized',
  ]
)

conf_data = configuration_data()
conf_data.set_quoted('BACKUP_BUSNAME', 'xyz.openbmc_project.TwoFactorAuthentication.WebTwoFactorAuthentication',
                       description : 'The DBus busname to own.')

conf_header = configure_file(output: 'config.h',configuration: conf_data)

sdbusplus = dependency('sdbusplus')
sdeventplus = dependency('sdeventplus')
systemd = dependency('systemd')
phosphor_logging_dep = dependency('phosphor-logging')
tests_opt = get_option('tests')
if tests_opt.enabled()
    phosphor_dbus_interfaces_proj = subproject('phosphor_dbus_interfaces', required: true)
    phosphor_dbus_interfaces_dep = phosphor_dbus_interfaces_proj.get_variable('phosphor_dbus_interfaces_dep')
else
    phosphor_dbus_interfaces_dep = dependency('phosphor-dbus-interfaces')
endif
cpp = meson.get_compiler('cpp')

test_env = [
  'MALLOC_CHECK_=2',
]

executable(
  'WebTwoFactorAuthentication',
  'WebTwoFactorAuthentication.hpp',
  'WebTwoFactorAuthentication.cpp',
  dependencies: [
    sdbusplus,
    sdeventplus,
    phosphor_dbus_interfaces_dep,
    phosphor_logging_dep,
  ],
  link_args: ['-lcrypt', '-lstdc++fs', '-lpam', '-lmcheck'],
  cpp_args: ['-DBOOST_ALL_NO_LIB', '-DBOOST_SYSTEM_NO_DEPRECATED', '-DBOOST_ERROR_CODE_HEADER_ONLY'],
  install: true,
)


if tests_opt.enabled()
  subdir('tests')
endif
