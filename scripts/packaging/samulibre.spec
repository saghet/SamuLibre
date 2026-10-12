Name:           samulibre
Version:        0.1.0
Release:        1%{?dist}
Summary:        Suite de Seguridad y Antivirus Open Source

License:        GPL-3.0
URL:            https://github.com/samulibre/samulibre
Source0:        %{name}-%{version}.tar.gz

Requires:       webkit2gtk4.1, gtk3, tor, iptables, zenity
Recommends:     policycoreutils, firewalld

%description
SamuLibre es una solución integral de ciberdefensa ligera y modular para Linux y Windows:
 - Antivirus multipatrón heurístico de alto rendimiento.
 - Escudo EDR con canarios señuelo anti-ransomware.
 - Parches Virtuales en memoria y mitigaciones sysctl.
 - VPN Tor integrada con doble cifrado y Kill-Switch.

%prep
# No source unpacking needed for binary packaging

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}/usr/bin
mkdir -p %{buildroot}/usr/share/applications
mkdir -p %{buildroot}/usr/share/icons/hicolor/512x512/apps
mkdir -p %{buildroot}/usr/share/samulibre/data/ui
mkdir -p %{buildroot}/usr/share/samulibre/data/signatures
mkdir -p %{buildroot}/usr/lib/systemd/user

install -m 755 samulibre-gui %{buildroot}/usr/bin/samulibre-gui
install -m 755 samulibre-cli %{buildroot}/usr/bin/samulibre-cli
install -m 644 samulibre.desktop %{buildroot}/usr/share/applications/samulibre.desktop
install -m 644 icon.png %{buildroot}/usr/share/icons/hicolor/512x512/apps/samulibre.png
install -m 644 samulibre.service %{buildroot}/usr/lib/systemd/user/samulibre.service
cp -r ui/* %{buildroot}/usr/share/samulibre/data/ui/
if [ -d signatures ]; then
    cp -r signatures/* %{buildroot}/usr/share/samulibre/data/signatures/ || true
fi

%files
/usr/bin/samulibre-gui
/usr/bin/samulibre-cli
/usr/share/applications/samulibre.desktop
/usr/share/icons/hicolor/512x512/apps/samulibre.png
/usr/share/samulibre/data/ui/*
/usr/lib/systemd/user/samulibre.service

%post
update-desktop-database -q /usr/share/applications || true
gtk-update-icon-cache -q -t -f /usr/share/icons/hicolor || true

%preun
pkill -f samulibre-gui || true

%changelog
* Mon Oct 12 2026 SamuLibre Security Team <security@samulibre.org> - 0.1.0-1
- Initial Linux release supporting Red Hat Enterprise Linux and Fedora
