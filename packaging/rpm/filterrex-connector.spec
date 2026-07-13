Name:           filterrex-connector
Version:        %{_version}
Release:        1%{?dist}
Summary:        FilterREX Connector Host — Enterprise Infrastructure Agent
License:        Apache-2.0
URL:            https://san.filterrex.com

BuildArch:      %{_build_arch}
Requires:       systemd

%{?systemd_requires}

%description
Lightweight, outbound-only agent for read-only Brocade SAN fabric evidence
collection with the FilterREX platform. It enrolls once, connects outbound
only, and needs no inbound firewall ports. All collection is read-only.

Binary: /usr/bin/filterrex-connector
Config: /etc/filterrex/connector.env
Service: filterrex-connector.service

%install
# Populated by build-packages.sh before rpmbuild
cp -a %{_stagedir}/* %{buildroot}/

%files
%attr(0755,root,root) /usr/bin/filterrex-connector
%attr(0644,root,root) %{_unitdir}/filterrex-connector.service
%dir %attr(0750,root,filterrex) /etc/filterrex
%config(noreplace) %attr(0640,root,filterrex) /etc/filterrex/connector.env

# ── Lifecycle scriptlets using systemd macros ──

%pre
# Create system user and group
getent group filterrex >/dev/null 2>&1 || groupadd --system filterrex
getent passwd filterrex >/dev/null 2>&1 || \
  useradd --system --gid filterrex --no-create-home \
    --home-dir /nonexistent --shell /sbin/nologin \
    --comment "FilterREX Connector Host" filterrex
mkdir -p /etc/filterrex
chown root:filterrex /etc/filterrex
chmod 0750 /etc/filterrex

%post
%systemd_post filterrex-connector.service
echo ""
echo "============================================================"
echo "  FilterREX Connector Host installed successfully."
echo ""
echo "  Next steps:"
echo "    1. Edit /etc/filterrex/connector.env"
echo "       Set FILTERREX_ENROLLMENT_TOKEN (or CONNECTOR_TOKEN)"
echo ""
echo "    2. Enable and start the service:"
echo "       sudo systemctl enable --now filterrex-connector"
echo "============================================================"
echo ""

%preun
%systemd_preun filterrex-connector.service

%postun
%systemd_postun_with_restart filterrex-connector.service

%changelog
