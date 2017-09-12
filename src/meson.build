io_systemd_devices_sources = files('''
        main.c
        util.h
'''.split())

io_systemd_devices_varlink_c_inc = custom_target(
        'io.systemd.devices.varlink',
        input : 'io.systemd.devices.varlink',
        output : 'io.systemd.devices.varlink.c.inc',
        command : [varlink_wrapper_py, '@INPUT@', '@OUTPUT@'])

exe = executable(
        'io.systemd.devices',
        io_systemd_devices_sources,
        io_systemd_devices_varlink_c_inc,
        dependencies : [
                libvarlink,
                libudev
        ],
        install : true)
