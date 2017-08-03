%define build_date %(date +"%%a %%b %%d %%Y")
%define build_timestamp %(date +"%%Y%%m%%d.%%H%m%%S")

Name:           io.systemd.devices
Version:        1
Release:        %{build_timestamp}%{?dist}
Summary:        Systemd Device Interface
License:        ASL2.0
URL:            https://github.com/varlink/io.systemd.devices
Source0:        https://github.com/varlink/io.systemd.devices/archive/v%{version}.tar.gz
BuildRequires:  autoconf automake pkgconfig
BuildRequires:  libvarlink-devel
BuildRequires:  libudev-devel

%description
Service to enumerate and monitor kernel devices.

%prep
%setup -q

%build
./autogen.sh
%configure
make %{?_smp_mflags}

%install
%make_install

%files
%license AUTHORS
%license COPYRIGHT
%license LICENSE
%{_bindir}/io.systemd.devices

%changelog
* %{build_date} <info@varlink.org> %{version}-%{build_timestamp}
- %{name} %{version}
