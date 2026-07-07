Name:           hunt-land
Version:        %{hunt_version}
Release:        1%{?dist}
Summary:        Living-off-the-Land forensic hunter for Blue Team defenders
License:        TBD
URL:            https://github.com/r-sandy/hunt-land
BuildArch:      noarch
Requires:       bash

%description
Read-only compromise-assessment toolkit for hosts where AV/EDR shows no
file-based alerts but native tooling (bash, cron, systemd, curl, LOLBins)
is suspected of being abused. Runs a six-phase hunt pipeline and emits a
ranked Compromise Assessment Report mapped to MITRE ATT&CK.

%prep
# Sources are staged by build-rpm.sh via %{repo_root}; nothing to unpack.

%install
mkdir -p %{buildroot}%{_bindir} %{buildroot}%{_prefix}/lib/hunt-land
for t in hunt-land hunt-procs hunt-net hunt-persist hunt-lolbin hunt-memory hunt-intel; do
    install -m 0755 %{repo_root}/tools/bin/$t %{buildroot}%{_bindir}/$t
done
install -m 0644 %{repo_root}/tools/lib/hunt-common.sh \
    %{buildroot}%{_prefix}/lib/hunt-land/hunt-common.sh

%files
%{_bindir}/hunt-land
%{_bindir}/hunt-procs
%{_bindir}/hunt-net
%{_bindir}/hunt-persist
%{_bindir}/hunt-lolbin
%{_bindir}/hunt-memory
%{_bindir}/hunt-intel
%dir %{_prefix}/lib/hunt-land
%{_prefix}/lib/hunt-land/hunt-common.sh
%doc README.md

%changelog
* Mon Jul 07 2026 r-sandy <symlir.diglm@gmail.com> - 1.0.0-1
- Initial package
