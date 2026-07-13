Name:           forgeai-host
Version:        %{_version}
Release:        1%{?dist}
Summary:        ForgeAI Connector Host — Enterprise Infrastructure Agent
License:        MIT
URL:            https://forgeai.com

BuildArch:      %{_build_arch}
Requires:       systemd

%{?systemd_requires}

%description
Lightweight outbound-only agent for bridging on-premise infrastructure
with the ForgeAI platform. Supports multiple simultaneous targets
including Prometheus, Grafana, iDRAC, and other enterprise systems.

Binary: /usr/bin/forgeai-host
Config: /etc/forgeai/connector.env
Service: forgeai-host.service

%install
# Populated by build-packages.sh before rpmbuild
cp -a %{_stagedir}/* %{buildroot}/

%files
%attr(0755,root,root) /usr/bin/forgeai-host
%attr(0644,root,root) %{_unitdir}/forgeai-host.service
%dir %attr(0750,root,forgeai) /etc/forgeai
%config(noreplace) %attr(0640,root,forgeai) /etc/forgeai/connector.env

# ── Lifecycle scriptlets using systemd macros ──

%pre
# Create system user and group
getent group forgeai >/dev/null 2>&1 || groupadd --system forgeai
getent passwd forgeai >/dev/null 2>&1 || \
  useradd --system --gid forgeai --no-create-home \
    --home-dir /nonexistent --shell /sbin/nologin \
    --comment "ForgeAI Connector Host" forgeai
mkdir -p /etc/forgeai
chown root:forgeai /etc/forgeai
chmod 0750 /etc/forgeai

%post
%systemd_post forgeai-host.service
echo ""
echo "============================================================"
echo "  ForgeAI Connector Host installed successfully."
echo ""
echo "  Next steps:"
echo "    1. Edit /etc/forgeai/connector.env"
echo "       Set FORGEAI_ENROLLMENT_TOKEN (or CONNECTOR_TOKEN)"
echo ""
echo "    2. Enable and start the service:"
echo "       sudo systemctl enable --now forgeai-host"
echo "============================================================"
echo ""

%preun
%systemd_preun forgeai-host.service

%postun
%systemd_postun_with_restart forgeai-host.service

%changelog
