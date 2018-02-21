#include "com.redhat.devices.varlink.c.inc"
#include "util.h"

#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <libudev.h>
#include <time.h>
#include <varlink.h>

enum {
        ERROR_PANIC = 1,
        ERROR_MISSING_ADDRESS,
        ERROR_CANCELED
};

static const char *error_strings[] = {
        [ERROR_PANIC]           = "Panic",
        [ERROR_MISSING_ADDRESS] = "MissingAddress",
        [ERROR_CANCELED] = "Canceled"
};

static long exit_error(long error) {
        fprintf(stderr, "Error: %s\n", error_strings[error]);

        return error;
}

typedef struct {
        VarlinkService *service;

        int epoll_fd;
        int signal_fd;
        int uevent_fd;

        struct udev *udev;
} Manager;

static void manager_free(Manager *m) {
        if (m->epoll_fd >= 0)
                close(m->epoll_fd);

        if (m->signal_fd >= 0)
                close(m->signal_fd);

        if (m->uevent_fd >= 0)
                close(m->uevent_fd);

        if (m->service)
                varlink_service_free(m->service);

        if (m->udev)
                udev_unref(m->udev);

        free(m);
}

static void manager_freep(Manager **mp) {
        if (*mp)
                manager_free(*mp);
}

static long manager_new(Manager **mp) {
        _cleanup_(manager_freep) Manager *m = NULL;

        m = calloc(1, sizeof(Manager));

        m->udev = udev_new();

        m->epoll_fd = -1;
        m->signal_fd = -1;
        m->uevent_fd = -1;

        *mp = m;
        m = NULL;

        return 0;
}

typedef struct {
        Manager *m;
        VarlinkCall *call;
        uint64_t flags;
        struct udev_monitor *monitor;
} Peer;

static long epoll_add(int epoll_fd, int fd, void *ptr) {
        struct epoll_event event = {
                .events = EPOLLIN,
                .data = {
                        .ptr = ptr
                }
        };

        return epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &event);
}

static void peer_free(Peer *peer) {
        if (peer->monitor) {
                epoll_ctl(peer->m->epoll_fd, EPOLL_CTL_DEL, udev_monitor_get_fd(peer->monitor), NULL);
                udev_monitor_unref(peer->monitor);
        }

        free(peer);
}

static void peer_freep(Peer **peerp) {
        if (*peerp)
                peer_free(*peerp);
}

static void connection_closed(VarlinkCall *call, void *userdata) {
        Peer *peer = userdata;

        peer_free(peer);
}

static long peer_new(Peer **peerp,
                     Manager *m,
                     VarlinkCall *call,
                     uint64_t flags,
                     const char *subsystem, const char *devtype) {
        _cleanup_(peer_freep) Peer *peer = NULL;

        peer = calloc(1, sizeof(Peer));
        peer->m = m;
        peer->call = call;
        peer->flags = flags;
        varlink_call_set_connection_closed_callback(peer->call, connection_closed, peer);

        peer->monitor = udev_monitor_new_from_netlink(m->udev, "udev");
        if (!peer->monitor)
                return -errno;

        udev_monitor_filter_add_match_subsystem_devtype(peer->monitor, subsystem, devtype);
        udev_monitor_enable_receiving(peer->monitor);

        if (epoll_add(m->epoll_fd, udev_monitor_get_fd(peer->monitor), peer) < 0)
                return -errno;

        *peerp = peer;
        peer = NULL;

        return 0;
}

static long add_udev_device(VarlinkArray *devices, struct udev_device *d) {
        _cleanup_(varlink_object_unrefp) VarlinkObject *device = NULL;

        varlink_object_new(&device);
        varlink_object_set_string(device, "device_path", udev_device_get_devpath(d));
        varlink_object_set_string(device, "name", udev_device_get_sysname(d));
        varlink_object_set_string(device, "subsystem", udev_device_get_subsystem(d));
        if (udev_device_get_devnode(d))
                varlink_object_set_string(device, "node", udev_device_get_devnode(d));

        return varlink_array_append_object(devices, device);
}

static long peer_dispatch(Peer *peer) {
        struct udev_device *d;
        _cleanup_(varlink_object_unrefp) VarlinkObject *out = NULL;
        _cleanup_(varlink_array_unrefp) VarlinkArray *devices = NULL;

        d = udev_monitor_receive_device(peer->monitor);
        if (!d)
                return 0;

        varlink_array_new(&devices);
        varlink_object_new(&out);
        varlink_object_set_array(out, "devices", devices);
        varlink_object_set_string(out, "event", udev_device_get_action(d));

        add_udev_device(devices, d);
        udev_device_unref(d);

        return varlink_call_reply(peer->call,
                                  out,
                                  peer->flags & VARLINK_CALL_MORE ? VARLINK_REPLY_CONTINUES : 0);
}

static long com_redhat_devices_monitor(VarlinkService *service,
                                       VarlinkCall *call,
                                       VarlinkObject *parameters,
                                       uint64_t flags,
                                       void *userdata) {
        Manager *m= (Manager *)userdata;
        _cleanup_(peer_freep) Peer *peer = NULL;
        const char *subsystem = NULL;
        _cleanup_(varlink_object_unrefp) VarlinkObject *out = NULL;
        _cleanup_(varlink_array_unrefp) VarlinkArray *devices = NULL;
        struct udev_enumerate *e;
        struct udev_list_entry *list_entry;
        long r;

        varlink_object_get_string(parameters, "subsystem", &subsystem);

        r = peer_new(&peer, m, call, flags, subsystem, NULL);
        if (r < 0)
                return r;

        varlink_array_new(&devices);

        e = udev_enumerate_new(m->udev);
        udev_enumerate_add_match_subsystem(e, subsystem);
        udev_enumerate_scan_devices(e);

        udev_list_entry_foreach(list_entry, udev_enumerate_get_list_entry(e)) {
                struct udev_device *d;

                d = udev_device_new_from_syspath(m->udev, udev_list_entry_get_name(list_entry));
                if (!d)
                        continue;

                add_udev_device(devices, d);
                udev_device_unref(d);
        }

        udev_enumerate_unref(e);

        varlink_object_new(&out);
        varlink_object_set_string(out, "event", "current");
        varlink_object_set_array(out, "devices", devices);

        peer = NULL;

        return varlink_call_reply(call, out, flags & VARLINK_CALL_MORE ? VARLINK_REPLY_CONTINUES : 0);
}

static int make_signalfd(void) {
        sigset_t mask;

        sigemptyset(&mask);
        sigaddset(&mask, SIGTERM);
        sigaddset(&mask, SIGINT);
        sigprocmask(SIG_BLOCK, &mask, NULL);

        return signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
}

static long read_signal(int signal_fd) {
        struct signalfd_siginfo fdsi;
        long size;

        size = read(signal_fd, &fdsi, sizeof(struct signalfd_siginfo));
        if (size != sizeof(struct signalfd_siginfo))
                return -EIO;

        return fdsi.ssi_signo;
}

int main(int argc, char **argv) {
        _cleanup_(manager_freep) Manager *m = NULL;
        const char *address;
        int fd = -1;
        long r;

        r = manager_new(&m);
        if (r < 0)
                return exit_error(ERROR_PANIC);

        address = argv[1];
        if (!address)
                return exit_error(ERROR_MISSING_ADDRESS);

        /* An activator passed us our listen socket. */
        if (read(3, NULL, 0) == 0)
                fd = 3;

        r = varlink_service_new(&m->service,
                                "Red Hat",
                                "Device Interface",
                                VERSION,
                                "https://github.com/varlink/com.redhat.devices",
                                address,
                                fd);
        if (r < 0)
                return exit_error(ERROR_PANIC);

        r = varlink_service_add_interface(m->service, com_redhat_devices_varlink,
                                          "Monitor", com_redhat_devices_monitor, m,
                                          NULL);
        if (r <0 )
                return exit_error(ERROR_PANIC);

        m->signal_fd = make_signalfd();
        if (m->signal_fd < 0)
                return exit_error(ERROR_PANIC);

        m->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
        if (m->epoll_fd < 0 ||
            epoll_add(m->epoll_fd, varlink_service_get_fd(m->service), m->service) < 0 ||
            epoll_add(m->epoll_fd, m->signal_fd, NULL) < 0)
                return exit_error(ERROR_PANIC);

        for (;;) {
                struct epoll_event event;
                int n;

                n = epoll_wait(m->epoll_fd, &event, 1, -1);
                if (n < 0) {
                        if (errno == EINTR)
                                continue;

                        return exit_error(ERROR_PANIC);
                }

                if (n == 0)
                        continue;

                if (event.data.ptr == m->service) {
                        r = varlink_service_process_events(m->service);
                        if (r < 0) {
                                if (r != -EPIPE)
                                        return exit_error(ERROR_PANIC);
                        }
                } else if (event.data.ptr == NULL) {
                        switch (read_signal(m->signal_fd)) {
                                case SIGTERM:
                                case SIGINT:
                                        return exit_error(ERROR_CANCELED);

                                default:
                                        return exit_error(ERROR_PANIC);
                        }
                } else {
                        Peer *peer = event.data.ptr;

                        r = peer_dispatch(peer);
                        if (r < 0 && r != -EPIPE)
                                return exit_error(ERROR_PANIC);
                }
        }

        return EXIT_SUCCESS;
}
