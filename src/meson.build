com_redhat_devices_sources = files('''
        main.c
        util.h
'''.split())

com_redhat_devices_varlink_c_inc = custom_target(
        'com.redhat.devices.varlink',
        input : 'com.redhat.devices.varlink',
        output : 'com.redhat.devices.varlink.c.inc',
        command : [varlink_wrapper_py, '@INPUT@', '@OUTPUT@'])

exe = executable(
        'com.redhat.devices',
        com_redhat_devices_sources,
        com_redhat_devices_varlink_c_inc,
        dependencies : [
                libvarlink,
                libudev
        ],
        install : true)
