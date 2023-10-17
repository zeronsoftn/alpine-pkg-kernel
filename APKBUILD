# Maintainer: Natanael Copa <ncopa@alpinelinux.org>

_flavor=lts
pkgname=linux-$_flavor
pkgver=6.1.58
case $pkgver in
	*.*.*)	_kernver=${pkgver%.*};;
	*.*) _kernver=$pkgver;;
esac
pkgrel=0
pkgdesc="Linux lts kernel"
url="https://www.kernel.org"
depends="initramfs-generator"
_depends_dev="perl gmp-dev mpc1-dev mpfr-dev elfutils-dev bash flex bison zstd"
makedepends="$_depends_dev sed installkernel bc linux-headers linux-firmware-any openssl-dev>3 mawk
	diffutils findutils zstd pahole>=1.25 python3"
options="!strip"
_config=${config:-config-lts.${CARCH}}
source="https://cdn.kernel.org/pub/linux/kernel/v${pkgver%%.*}.x/linux-$_kernver.tar.xz
	0001-powerpc-config-defang-gcc-check-for-stack-protector-.patch
	0001-x86-Compress-vmlinux-with-zstd-19-instead-of-22.patch
	0001-kexec-add-kexec_load_disabled-boot-option.patch
	awk.patch
	ppc-notext.patch
	0001-tty-Move-sysctl-setup-into-core-tty-logic.patch
	0002-tty-Allow-TIOCSTI-to-be-disabled.patch
	0003-tty-Move-TIOCSTI-toggle-variable-before-kerndoc.patch

	lts.aarch64.config
	lts.armv7.config
	lts.x86.config
	lts.x86_64.config
	lts.ppc64le.config
	lts.s390x.config

	virt.aarch64.config
	virt.armv7.config
	virt.ppc64le.config
	virt.x86.config
	virt.x86_64.config
	"
subpackages="$pkgname-dev:_dev:$CBUILD_ARCH $pkgname-doc"
for _i in $source; do
	case $_i in
	*.$CARCH.config)
		_f=${_i%."$CARCH".config}
		_flavors="$_flavors $_f"
		if [ "linux-$_f" != "$pkgname" ]; then
			subpackages="$subpackages linux-$_f::$CBUILD_ARCH linux-$_f-dev:_dev:$CBUILD_ARCH"
		fi
		;;
	esac
done
builddir="$srcdir"/linux-$_kernver

if [ "${pkgver%.0}" = "$pkgver" ]; then
	source="$source
	https://cdn.kernel.org/pub/linux/kernel/v${pkgver%%.*}.x/patch-$pkgver.xz"
fi
arch="all !armhf !riscv64"
license="GPL-2.0-only"

# secfixes:
#   6.1.27-r3:
#     - CVE-2023-32233
#   5.10.4-r0:
#     - CVE-2020-29568
#     - CVE-2020-29569
#   5.15.74-r0:
#     - CVE-2022-41674
#     - CVE-2022-42719
#     - CVE-2022-42720
#     - CVE-2022-42721
#     - CVE-2022-42722

prepare() {
	if [ "$_kernver" != "$pkgver" ]; then
		msg "Applying patch-$pkgver.xz"
		unxz -c < "$srcdir"/patch-$pkgver.xz | patch -p1 -N
	fi

	default_prepare

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
	echo "-$pkgrel-$_flavor" > "$_builddir"/localversion-alpine

	cp "$srcdir"/$_config "$_builddir"/.config
	msg "Configuring $_flavor kernel ($_arch)"
	make -C "$srcdir"/linux-$_kernver \
		O="$_builddir" \
		ARCH="$(_kernelarch $_arch)" \
		olddefconfig

	if grep "CONFIG_MODULE_SIG=y" "$_builddir"/.config >/dev/null; then
		if [ -f "$KERNEL_SIGNING_KEY" ]; then
			sed -i -e "s:^CONFIG_MODULE_SIG_KEY=.*:CONFIG_MODULE_SIG_KEY=\"$KERNEL_SIGNING_KEY\":" \
				"$_builddir"/.config
			msg "Using $KERNEL_SIGNING_KEY to sign $_flavor kernel ($_arch) modules"
		else
			warning "KERNEL_SIGNING_KEY was not set. A signing key will be generated, but 3rd"
			warning "party modules can not be signed"
		fi
	fi
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
	for _config in ${CONFIGS:-$(listconfigs)}; do
		msg "updating $_config"
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
		fi
		env | grep ^CONFIG_ >> "$_builddir"/.config || true
		make -j1 -C "$srcdir"/linux-$_kernver \
			O="$_builddir" \
			ARCH="$(_kernelarch $_arch)" \
			$actions savedefconfig

		cp "$_builddir"/defconfig "$startdir"/$_config
	done
}

build() {
	unset LDFLAGS
	# for some reason these sometimes leak into the kernel build,
	# -Werror=format-security breaks some stuff
	unset CFLAGS CPPFLAGS CXXFLAGS
	export KBUILD_BUILD_TIMESTAMP="$(date -Ru${SOURCE_DATE_EPOCH:+d @$SOURCE_DATE_EPOCH})"
	for i in $_flavors; do
		_prepareconfig "$i" "$CARCH"
	done
	for i in $_flavors; do
		msg "Building $i kernel"
		cd "$srcdir"/build-$i.$CARCH

		# set org in cert for modules signing
		# https://www.kernel.org/doc/html/v6.1/admin-guide/module-signing.html#generating-signing-keys
		mkdir -p certs
		sed -e 's/#O = Unspecified company/O = alpinelinux.org/' \
			"$srcdir"/linux-$_kernver/certs/default_x509.genkey \
			> certs/x509.genkey

		make ARCH="$(_kernelarch $CARCH)" \
			CC="${CC:-gcc}" \
			AWK="${AWK:-mawk}" \
			KBUILD_BUILD_VERSION="$((pkgrel + 1 ))-Alpine"
	done
}

_package() {
	local _buildflavor="$1" _outdir="$2"
	export KBUILD_BUILD_TIMESTAMP="$(date -Ru${SOURCE_DATE_EPOCH:+d @$SOURCE_DATE_EPOCH})"

	cd "$srcdir"/build-$_buildflavor.$CARCH
	local _abi_release="$(make -s kernelrelease)"
	# modules_install seems to regenerate a defect Modules.symvers on s390x. Work
	# around it by backing it up and restore it after modules_install
	cp Module.symvers Module.symvers.backup

	mkdir -p "$_outdir"/boot "$_outdir"/lib/modules

	local _install
	case "$CARCH" in
		arm*|aarch64) _install="zinstall dtbs_install";;
		*) _install=install;;
	esac

	make modules_install $_install \
		ARCH="$(_kernelarch $CARCH)" \
		INSTALL_MOD_PATH="$_outdir" \
		INSTALL_MOD_STRIP=1 \
		INSTALL_PATH="$_outdir"/boot \
		INSTALL_DTBS_PATH="$_outdir/boot/dtbs-$_buildflavor"

	cp Module.symvers.backup Module.symvers

	rm -f "$_outdir"/lib/modules/"$_abi_release"/build \
		"$_outdir"/lib/modules/"$_abi_release"/source
	rm -rf "$_outdir"/lib/firmware

	install -D -m644 include/config/kernel.release \
		"$_outdir"/usr/share/kernel/$_buildflavor/kernel.release
}

# main flavor installs in $pkgdir
package() {
	depends="$depends linux-firmware-any"

	_package lts "$pkgdir"

	# copy files for linux-lts-doc sub package
	mkdir -p "$pkgdir"/usr/share/doc
	cp -r "$srcdir"/linux-"$_kernver"/Documentation \
		"$pkgdir"/usr/share/doc/linux-doc-"$pkgver"/
	# remove files that aren't part of the documentation itself
	for nondoc in \
		.gitignore conf.py docutils.conf \
		dontdiff Kconfig Makefile
	do
		rm "$pkgdir"/usr/share/doc/linux-doc-"$pkgver"/"$nondoc"
	done
	# create /usr/share/doc/linux-doc symlink
	cd "$pkgdir"/usr/share/doc; ln -s linux-doc-"$pkgver" linux-doc
}

# subflavors install in $subpkgdir
virt() {
	_package virt "$subpkgdir"
}

_dev() {
	local _flavor=$(echo $subpkgname | sed -E 's/(^linux-|-dev$)//g')
	local _builddir="$srcdir"/build-$_flavor.$CARCH
	local _abi_release="$(make -C "$_builddir" -s kernelrelease)"
	# copy the only the parts that we really need for build 3rd party
	# kernel modules and install those as /usr/src/linux-headers,
	# simlar to what ubuntu does
	#
	# this way you dont need to install the 300-400 kernel sources to
	# build a tiny kernel module
	#
	pkgdesc="Headers and script for third party modules for $_flavor kernel"
	depends="$_depends_dev"
	local dir="$subpkgdir"/usr/src/linux-headers-"$_abi_release"
	export KBUILD_BUILD_TIMESTAMP="$(date -Ru${SOURCE_DATE_EPOCH:+d @$SOURCE_DATE_EPOCH})"

	# first we import config, run prepare to set up for building
	# external modules, and create the scripts
	mkdir -p "$dir"
	cp -a "$_builddir"/.config "$_builddir"/localversion-alpine \
		"$dir"/

	install -D -t "$dir"/certs "$_builddir"/certs/signing_key.x509 || :

	make -C "$srcdir"/linux-$_kernver \
		O="$dir" \
		ARCH="$(_kernelarch $CARCH)" \
		AWK="${AWK:-mawk}" \
		prepare modules_prepare scripts

	# remove the stuff that points to real sources. we want 3rd party
	# modules to believe this is the sources
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

	find "arch/$_karch" -name include -type d -print | while IFS='' read -r folder; do
		find "$folder" -type f
	done | sort -u | cpio -pdm "$dir"

	install -Dm644 "$srcdir"/build-$_flavor.$CARCH/Module.symvers \
		"$dir"/Module.symvers

	# remove unneeded things
	msg "Removing documentation..."
	rm -r "$dir"/Documentation
	find "$dir" -type f -name '*.o' -printf 'Removing %P\n' -delete
	local _karch="$(_kernelarch $CARCH | sed 's/x86_64/x86/')"
	msg "Removing unneeded arch headers..."
	for i in "$dir"/arch/*; do
		if [ "${i##*/}" != "$_karch" ]; then
			echo "  ${i##*/}"
			rm -r "$i"
		fi
	done

	mkdir -p "$subpkgdir"/lib/modules/"$_abi_release"
	ln -sf /usr/src/linux-headers-"$_abi_release" \
		"$subpkgdir"/lib/modules/"$_abi_release"/build
}

sha512sums="
6ed2a73c2699d0810e54753715635736fc370288ad5ce95c594f2379959b0e418665cd71bc512a0273fe226fe90074d8b10d14c209080a6466498417a4fdda68  linux-6.1.tar.xz
a6c826e8c3884550fbe1dee3771b201b3395b073369f7fbfb5dc4aa5501e848b0bbc3a5ad80d932a6a50cbe0cfd579c75662f0c43ef79a38c1c6848db395c4c8  0001-powerpc-config-defang-gcc-check-for-stack-protector-.patch
55f732c01e10948b283eb1cc77ce3f1169428251075f8f5dd3100d8fda1f08b6b3850969b84b42a52468d4f7c7ec7b49d01f0dff3c20c30f2e9ac0c07071b9d3  0001-x86-Compress-vmlinux-with-zstd-19-instead-of-22.patch
5464cf4b2e251972091cc9d5138291a94298737e98ec24829829203fc879593b440a7cd1ca08e6d01debaab2887976cb5d38fae2fbe5149cef1735d5d73bb086  0001-kexec-add-kexec_load_disabled-boot-option.patch
15fca2343b57dcab247c5ad86175ae638bace41a803984170a4aca4f3ec70edf6399ce5c6de82ae0dfabd3430a7a7567941718806b6d5d56515ecc7d55b2a800  awk.patch
c74488940244ba032e741c370767467cfab93b89077b5dfccfed39b658f381e0995527e6c61de53b1c112b04ba647bfccf00f2e05c0637d3c703680a508821cc  ppc-notext.patch
f8582538a8482656138a0ae56b67a6d3cec09ff8d82a3f790ffa3fa7c37d0ae24a04f01f0ae1aec09838f86490907995c2568be7841a3821f0e64704f60153e5  0001-tty-Move-sysctl-setup-into-core-tty-logic.patch
0bfd2c138e997f25f821cd518263ad515fc303bbde37bcdb7dd651d30316c77652fec6fedb195102b8476b92b1e7269c143dad5df6431db49c4318375ad2e802  0002-tty-Allow-TIOCSTI-to-be-disabled.patch
8b245ec672a56dae7ce82f488880f6f3c0b65776177db663a29f26de752bf2cefe6b677e2cedbebd85e98d6f6e3d66b9f198a0d7a6042a20191b5ca8f4a749e7  0003-tty-Move-TIOCSTI-toggle-variable-before-kerndoc.patch
9d0cea43bb43ef2ae5ce1b231d3f0b5601c22c050aba9fb09ae5dcdc70b2a357d4cbc4145fe99351fe812cedce656021cbc21010fc14bd45bc462806526a49db  lts.aarch64.config
96eb129b984c68ae8534a56e4a395bf1c58deaacba6972150b821fac5819098fdd1847c4933b743ff40138f9e6a318ce91a6923b2bfcbfb231d546d37498827c  lts.armv7.config
d5d21a42207d86cef376e4aeab0d2886b48d83ebf3d8e02dbbe958e63a8e7791fa8fede5354de3655132cd76cc4fb1259532d4f92b1c96fa1fdef28d6813b759  lts.x86.config
fe54f38c63cec120ea5e7cd5cbb8a3ff73b8447083c0f007c6a553df65a580bdfc9dd528ca34c21759ddb5d7c0f4381d633cd13937a43ac9d58c39982302152c  lts.x86_64.config
f350c03e12614b2226f0416996bc9b32328bcb722690c82b5aadb893fda17edaf99d51bf298fbf4fb6a27bbc409055f59802de3fcffc7357c35aa8f80252b4b9  lts.ppc64le.config
9bfa5abbc186cecedc9b7da73f9deab8f8dc3c441ea29bdf5ca70c7417efb15f189ee2c1853db08d64db0d50fc417df9505833aa03b81e0078101fb634309a52  lts.s390x.config
f03a4ed754fc0bede7a4279fbe4fdc47b5945e336e41fce57f7130bf7e52995a08e33e1a881586cc5e260bf68ff5de3ed1aa1318b77ac9e50ba6895fe0d3be9d  virt.aarch64.config
d4323576ffeb7605346673f3f1bfe97bc8da8d00afc272ae6017ba2b5d6e4170004fddec155c993a85f66a3d0e9abeb7da95bbae1c1c9c6cc55235db7bc6d2d3  virt.armv7.config
f16ba6d9cb8d0e5b5527c6e4df468951237ee6d9c5af432b3a25b72c167bfb83d5941c54788ca9d6610a9cc203da4aa4ebb06e20e7a1d72263b12bd0996a8197  virt.ppc64le.config
f24432150e2bf3565a04be5034cfb7e6ae91012ca8cfe97c844055db6b637a8e35cc7273cc29c3168421e8636f0160c622e85e4ba858acc4276f9de434bbadff  virt.x86.config
d90e3fed0584accae7289c392d57c656aa2c03529ab1e27f6dc06a4a2e6047daf6f4319a911982a2d587c6f506d018b65c4f52e7a3b4870f2af351d4300c3f4a  virt.x86_64.config
205d165f16a95cd675dfb577906f12cbd40a0049cf2c83575a01eb9378146b10f86404d86552759597bb57f2272f74b0cb4098b896b8c2647cf759a59c47a30c  patch-6.1.58.xz
"
