gtest_dep = dependency('gtest', main: false, required: false)
gmock_dep = dependency('gmock', required: false)

if not gtest_dep.found() or not gmock_dep.found()
  cmake = import('cmake')
  opt_var = cmake.subproject_options()
  opt_var.add_cmake_defines({'CMAKE_CXX_FLAGS': '-Wno-pedantic'})
  opt_var.set_override_option('warning_level', '3')
  opt_var.set_override_option('werror', 'true')

  gtest_proj = cmake.subproject('gtest', options: opt_var, required: false)
  if gtest_proj.found()
    gtest_dep = declare_dependency(
      dependencies: [dependency('threads'), gtest_proj.dependency('gtest')]
    )
    gmock_dep = gtest_proj.dependency('gmock')
  else
    gtest_proj = subproject('gtest', required: true)
    gtest_dep = gtest_proj.get_variable('gtest_dep')
    gmock_dep = gtest_proj.get_variable('gmock_dep')
  endif
endif

phosphor_dbus_interfaces_dep = dependency('phosphor_dbus_interfaces', required: false)
if not phosphor_dbus_interfaces_dep.found()
  phosphor_dbus_interfaces_proj = subproject('phosphor_dbus_interfaces', required: true)
  phosphor_dbus_interfaces_dep = phosphor_dbus_interfaces_proj.get_variable('phosphor_dbus_interfaces_dep')
endif
sdbusplus = dependency('sdbusplus')
sdeventplus = dependency('sdeventplus')
phosphor_logging_dep = dependency('phosphor-logging')

test_sources = [
  'test_main.cpp',
  'test_WebTwoFactorAuthentication.cpp',
]

unit_test_exe = executable(
  'unit_test_tfa',
  test_sources,
  include_directories: include_directories('..'),
  dependencies: [
    gtest_dep,
    gmock_dep,
    sdbusplus,
    sdeventplus,
    phosphor_dbus_interfaces_dep,
    phosphor_logging_dep,
  ],
  link_args: [
    '-lcrypt',
    '-lstdc++fs',
    '-lpam',
    '-lmcheck',
    '-Wl,--allow-multiple-definition',
  ],
  cpp_args: [
    '-DBOOST_ALL_NO_LIB',
    '-DBOOST_SYSTEM_NO_DEPRECATED',
    '-DBOOST_ERROR_CODE_HEADER_ONLY',
  ],
)

test('unit_test_tfa', unit_test_exe)
