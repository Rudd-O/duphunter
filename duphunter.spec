# See https://docs.fedoraproject.org/en-US/packaging-guidelines/Python/#_example_spec_file

%define debug_package %{nil}

%define _name duphunter

%define mybuildnumber %{?build_number}%{?!build_number:1}

Name:           %{_name}
Version:        0.1.19.1
Release:        %{mybuildnumber}%{?dist}
Summary:        An application that finds and lets you delete duplicate files

License:        GPLv3+
URL:            https://github.com/Rudd-O/%{_name}
Source:         %{_name}-%{version}.tar.gz

BuildArch:      noarch
BuildRequires:  python3-devel python3-setuptools
BuildRequires:  desktop-file-utils
BuildRequires:  coreutils

Requires:       python3-qt5-base

%global _description %{expand:
Duphunter is a very simple application that finds and lets you delete duplicate
files interactively, using a very efficient list interface where you can mark
files for preservation or deletion, and later commit your changes.

The scanning process should scale well into the millions of files.}

%description %_description

%prep
%autosetup -p1

%generate_buildrequires
%pyproject_buildrequires -t


%build
%pyproject_wheel


%install
%pyproject_install

mkdir -p %{buildroot}%{_datadir}/applications
desktop-file-install --dir=%{buildroot}%{_datadir}/applications src/%{_name}/applications/%{_name}.desktop

%pyproject_save_files %{_name}
echo %{_bindir}/%{_name} >> %{pyproject_files}
echo %{_datadir}/applications/%{_name}.desktop >> %{pyproject_files}


%check
%tox


%files -f %{pyproject_files}

%doc README.md


%changelog
* Wed Feb 21 2024 Manuel Amador <rudd-o@rudd-o.com> 0.0.26-1
- First RPM packaging release
