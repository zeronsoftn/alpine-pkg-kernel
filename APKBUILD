# Maintainer: Natanael Copa <ncopa@alpinelinux.org>

_flavor=zeron
pkgname=linux-${_flavor}
pkgver=5.15.41
case $pkgver in
	*.*.*)	_kernver=${pkgver%.*};;
	*.*) _kernver=$pkgver;;
esac
pkgrel=0
pkgdesc="Linux zeron kernel"
url="https://www.kernel.org"
depends="mkinitfs>=3.6.0"
_depends_dev="perl gmp-dev mpc1-dev mpfr-dev elfutils-dev bash flex bison zstd"
makedepends="$_depends_dev sed installkernel bc linux-headers linux-firmware-any openssl1.1-compat-dev mawk
	diffutils findutils zstd"
options="!strip"
_config=${config:-config-lts.${CARCH}}
install=
source="http://cdn.kernel.org/pub/linux/kernel/v${pkgver%%.*}.x/linux-$_kernver.tar.xz
	0001-powerpc-config-defang-gcc-check-for-stack-protector-.patch
	0002-lockdown-also-lock-down-previous-kgdb-use.patch
	vmlinux-zstd.patch

	zeron.aarch64.config
	zeron.x86.config
	zeron.x86_64.config

	zeron-uefi-certs.pem
	"
subpackages="$pkgname-dev:_dev:$CBUILD_ARCH"
_flavors=
for _i in $source; do
	case $_i in
	*.$CARCH.config)
		_f=${_i%.$CARCH.config}
		_flavors="$_flavors ${_f}"
		if [ "linux-$_f" != "$pkgname" ]; then
			subpackages="$subpackages linux-${_f}::$CBUILD_ARCH linux-${_f}-dev:_dev:$CBUILD_ARCH"
		fi
		;;
	esac
done

if [ "${pkgver%.0}" = "$pkgver" ]; then
	source="$source
	http://cdn.kernel.org/pub/linux/kernel/v${pkgver%%.*}.x/patch-$pkgver.xz"
fi
arch="all !armhf !riscv64"
license="GPL-2.0"

# secfixes:
#   5.10.4-r0:
#     - CVE-2020-29568
#     - CVE-2020-29569

prepare() {
	local _patch_failed=
	cd "$srcdir"/linux-$_kernver
	if [ "$_kernver" != "$pkgver" ]; then
		msg "Applying patch-$pkgver.xz"
		unxz -c < "$srcdir"/patch-$pkgver.xz | patch -p1 -N
	fi

	# first apply patches in specified order
	for i in $source; do
		case $i in
		*.patch)
			msg "Applying $i..."
			if ! patch -s -p1 -N -i "$srcdir"/$i; then
				echo $i >>failed
				_patch_failed=1
			fi
			;;
		esac
	done

	if ! [ -z "$_patch_failed" ]; then
		error "The following patches failed:"
		cat failed
		return 1
	fi
	
	cat $srcdir/zeron-uefi-certs.pem > $srcdir/signing_certs.pem

	# remove localversion from patch if any
	rm -f localversion*
}

_kernelarch() {
	local arch="$1"
	case "$arch" in
		aarch64*) arch="arm64" ;;
		arm*) arch="arm" ;;
		mips*) arch="mips" ;;
		ppc*) arch="powerpc" ;;
		s390*) arch="s390" ;;
	esac
	echo "$arch"
}

_prepareconfig() {
	local _flavor="$1"
	local _arch="$2"
	local _config=$_flavor.$_arch.config
	local _builddir="$srcdir"/build-$_flavor.$_arch
	mkdir -p "$_builddir"
	echo "-$pkgrel-$_flavor" > "$_builddir"/localversion-alpine \
		|| return 1

	cp "$srcdir"/$_config "$_builddir"/.config
	msg "Configuring $_flavor kernel ($_arch)"
	make -C "$srcdir"/linux-$_kernver \
		O="$_builddir" \
		ARCH="$(_kernelarch $_arch)" \
		olddefconfig
}

listconfigs() {
	for i in $source; do
		case "$i" in
			*.config) echo $i;;
		esac
	done
}

prepareconfigs() {
	for _config in $(listconfigs); do
		local _flavor=${_config%%.*}
		local _arch=${_config%.config}
		_arch=${_arch#*.}
		local _builddir="$srcdir"/build-$_flavor.$_arch
		_prepareconfig "$_flavor" "$_arch"
	done
}

# this is supposed to be run before version is bumped so we can compare
# what new kernel config knobs are introduced
prepareupdate() {
	clean && fetch && unpack && prepare && deps
	prepareconfigs
	rm -r "$srcdir"/linux-$_kernver
}

updateconfigs() {
	if ! [ -d "$srcdir"/linux-$_kernver ]; then
		deps && fetch && unpack && prepare
	fi
	for _config in $(listconfigs); do
		local _flavor=${_config%%.*}
		local _arch=${_config%.config}
		_arch=${_arch#*.}
		local _builddir="$srcdir"/build-$_flavor.$_arch
		mkdir -p "$_builddir"
		echo "-$pkgrel-$_flavor" > "$_builddir"/localversion-alpine
		local actions="listnewconfig oldconfig"
		if ! [ -f "$_builddir"/.config ]; then
			cp "$srcdir"/$_config "$_builddir"/.config
			actions="olddefconfig"
			env | grep ^CONFIG_ >> "$_builddir"/.config || true
		fi
		make -j1 -C "$srcdir"/linux-$_kernver \
			O="$_builddir" \
			ARCH="$(_kernelarch $_arch)" \
			$actions savedefconfig

		cp "$_builddir"/defconfig "$startdir"/$_config
	done
}

build() {
	unset LDFLAGS
	export KBUILD_BUILD_TIMESTAMP="$(date -Ru${SOURCE_DATE_EPOCH:+d @$SOURCE_DATE_EPOCH})"
	for i in $_flavors; do
		_prepareconfig "$i" "$CARCH"
	done
	for i in $_flavors; do
		msg "Building $i kernel"
		cd "$srcdir"/build-$i.$CARCH
		make ARCH="$(_kernelarch $CARCH)" \
			CC="${CC:-gcc}" \
			AWK="${AWK:-mawk}" \
			KBUILD_BUILD_VERSION="$((pkgrel + 1 ))-Alpine"
	done
}

_package() {
	local _buildflavor="$1" _outdir="$2"
	local _abi_release=${pkgver}-${pkgrel}-${_buildflavor}
	export KBUILD_BUILD_TIMESTAMP="$(date -Ru${SOURCE_DATE_EPOCH:+d @$SOURCE_DATE_EPOCH})"

	cd "$srcdir"/build-$_buildflavor.$CARCH
	# modules_install seems to regenerate a defect Modules.symvers on s390x. Work
	# around it by backing it up and restore it after modules_install
	cp Module.symvers Module.symvers.backup

	mkdir -p "$_outdir"/boot "$_outdir"/lib/modules

	local _install
	case "$CARCH" in
		arm*|aarch64) _install="zinstall dtbs_install";;
		*) _install=install;;
	esac

	make -j1 modules_install $_install \
		ARCH="$(_kernelarch $CARCH)" \
		INSTALL_MOD_PATH="$_outdir" \
		INSTALL_PATH="$_outdir"/boot \
		INSTALL_DTBS_PATH="$_outdir/boot/dtbs-$_buildflavor"

	cp Module.symvers.backup Module.symvers

	rm -f "$_outdir"/lib/modules/${_abi_release}/build \
		"$_outdir"/lib/modules/${_abi_release}/source
	rm -rf "$_outdir"/lib/firmware

	install -D -m644 include/config/kernel.release \
		"$_outdir"/usr/share/kernel/$_buildflavor/kernel.release
}

# main flavor installs in $pkgdir
package() {
	depends="$depends linux-firmware-any"

	_package zeron "$pkgdir"

	# sign vmlinuz
	if [ -n "${VMLINUZ_SIGN_TOOL:-}" ]; then
		${VMLINUZ_SIGN_TOOL} "$pkgdir/boot/vmlinuz-zeron"
	fi
}

# subflavors install in $subpkgdir
# virt() {
# 	_package virt "$subpkgdir"
# }

_dev() {
	local _flavor=$(echo $subpkgname | sed -E 's/(^linux-|-dev$)//g')
	local _abi_release=${pkgver}-${pkgrel}-$_flavor
	# copy the only the parts that we really need for build 3rd party
	# kernel modules and install those as /usr/src/linux-headers,
	# simlar to what ubuntu does
	#
	# this way you dont need to install the 300-400 kernel sources to
	# build a tiny kernel module
	#
	pkgdesc="Headers and script for third party modules for $_flavor kernel"
	depends="$_depends_dev"
	local dir="$subpkgdir"/usr/src/linux-headers-${_abi_release}
	export KBUILD_BUILD_TIMESTAMP="$(date -Ru${SOURCE_DATE_EPOCH:+d @$SOURCE_DATE_EPOCH})"

	# first we import config, run prepare to set up for building
	# external modules, and create the scripts
	mkdir -p "$dir"
	local _builddir="$srcdir"/build-$_flavor.$CARCH
	cp -a "$_builddir"/.config "$_builddir"/localversion-alpine \
		"$dir"/

	make -j1 -C "$srcdir"/linux-$_kernver \
		O="$dir" \
		ARCH="$(_kernelarch $CARCH)" \
		prepare modules_prepare scripts

	# remove the stuff that points to real sources. we want 3rd party
	# modules to believe this is the soruces
	rm "$dir"/Makefile "$dir"/source

	# copy the needed stuff from real sources
	#
	# this is taken from ubuntu kernel build script
	# http://kernel.ubuntu.com/git/ubuntu/ubuntu-zesty.git/tree/debian/rules.d/3-binary-indep.mk
	cd "$srcdir"/linux-$_kernver
	find .  -path './include/*' -prune \
		-o -path './scripts/*' -prune -o -type f \
		\( -name 'Makefile*' -o -name 'Kconfig*' -o -name 'Kbuild*' -o \
		   -name '*.sh' -o -name '*.pl' -o -name '*.lds' -o -name 'Platform' \) \
		-print | cpio -pdm "$dir"

	cp -a scripts include "$dir"

	find $(find arch -name include -type d -print) -type f \
		| cpio -pdm "$dir"

	install -Dm644 "$srcdir"/build-$_flavor.$CARCH/Module.symvers \
		"$dir"/Module.symvers

	mkdir -p "$subpkgdir"/lib/modules/${_abi_release}
	ln -sf /usr/src/linux-headers-${_abi_release} \
		"$subpkgdir"/lib/modules/${_abi_release}/build
}

sha512sums="
d25ad40b5bcd6a4c6042fd0fd84e196e7a58024734c3e9a484fd0d5d54a0c1d87db8a3c784eff55e43b6f021709dc685eb0efa18d2aec327e4f88a79f405705a  linux-5.15.tar.xz
214c54a839ae37849715520f4b1049f0df5366ca32522701b43afecfad116794c4542940ba32d389f28f2549d08c03d148f884cb8e565b75aa3c0cad6a4887b7  0001-powerpc-config-defang-gcc-check-for-stack-protector-.patch
e9291965579787ef2b21a9f076771662bbc367d45914b014b6658adda78ab68b115376b0fc41c9fc5b5bf3ab195934bbbfe67660f5bea961d16d2ea58b416074  0002-lockdown-also-lock-down-previous-kgdb-use.patch
d26d3f99fdcbd0f56e9af32a281870bbfd9fe6a12d17921ef3876e72bd1e92a3c131e06567078a45c11a41826b39d3068cc6f0e89f67d9e16a14825984869268  vmlinux-zstd.patch
e7d432f9a86433c2b3f300d6acaec4589ba89a851e57b8981723ace27c531db469f5833b23304472f467be35243efa62a06ea541c763062a471c2065ac354b3a  zeron.aarch64.config
1dcdccfe46af0691d78f5e2f2077be75be7a19584f30a8a58bec4e7592dc4881514d0a154e35007ea56a2928981a8704c9f7daab43be22964a0093dbdc9b05bd  zeron.x86.config
9fe8126b0e54e4083580779428f2a108072225b103a47e3bd63f592111fd735d5df2f7c2a6883c002053077d63be69efc22a23b071890081a6f9afb5cad2b1a2  zeron.x86_64.config
1c7ece228174f5c3049ec44cafa588117d6c470567a95ba4c926fa370b17b8a90256c40df657fc923ec32303268abeeb6249943eee69cad73be38156628aab6f  patch-5.15.41.xz
44c1c0950e7afbf0ca03961d6b871a49539d0de94b68b87c001472e1df1f7e7c3bab83ba1d6e0e5b6763bfb4a9a26e3445a5f944bf412db0f006fe3b700b4a71  zeron-uefi-certs.pem
"
