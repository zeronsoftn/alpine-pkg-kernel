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
	0004-arm64-add-kernel-config-option-to-lock-down-when.patch
	0005-efi-add-an-efi_secure_boot-flag-to-indicate-secure-b.patch
	0006-efi-lock-down-the-kernel-if-booted-in-secure-boot-mo.patch
	0007-mtd-disable-slram-and-phram-when-locked-down.patch

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
37907a2d1f1421ab48f4b61375be701aee0a235b3ed92655e31c3a79b84ae62daad9e9926096c985cd57680657cffce75d4ea26eabba016c23af95a02ee541af  0004-arm64-add-kernel-config-option-to-lock-down-when.patch
1d9c4532160a3f9ec029cef98b6e722bff6fe63267dcd61943019b01fcf83cc388ff28fb6c60171d983e148a98b13006b9c1842b52b2c7e43835abc4eb9fb44c  0005-efi-add-an-efi_secure_boot-flag-to-indicate-secure-b.patch
1a694ce0c5bd885911bf9f3deafd0342a386ef9fb7d5108ef8aa851abc539719a79d2cf1373a0ba0f84fbec26297fe0ab9ceeb34ed4d9334b5ac130af0b7613d  0006-efi-lock-down-the-kernel-if-booted-in-secure-boot-mo.patch
4ee571353d3968de76f38fa03b0553e4165ddd11f742afffa528f946a8a1119761fa40bd4e9fa05d993ac2ea1acee5c6972e330083854e35b66dc7f84aecdcc6  0007-mtd-disable-slram-and-phram-when-locked-down.patch
bdbfae154efc6e52a8aa8ad59d4df5ce3a5104f64b7889fd5de9dad1c054e7773c17468b8de50c4642a5794c8e0c51b1e9092169f8883e6ea5ba27f15d66e0c4  lts.aarch64.config
398347a66a224880e1270b7604150b19052f309860e0a30275f6a3eef1dda2994a93378987f92ab773b2721a0f2dfa6fb5922643dc9ff6cde839fdf11f1010ca  lts.armv7.config
5e8f65c5988266c137080c2681a6c2084cba4ee4ad3862f75e07f1bc641936a86947c2601e0d7a9613aa56d7b68be49f536f92236c9ed9daf35aa29d24d04640  lts.ppc64le.config
411b6baab014b20d35d0397a1fa18c603524e383a44f43c5bdda843329e532885c31cd4eda19424f6919d0e750b8a77ee34763b5b9b69bfdac385bd6cd097239  lts.s390x.config
f9933f7b6a59057ef53f9c5315adc6bdf12c6a4ddfb46bc7b7df523d1c75c166f9415b8f5e7ebb38f157f66c3721977c2685af12bcef7fec7f233b9af9da905a  lts.x86.config
38eedc9413bc69b18465caaa38b1a930c24de059f000feeefbb30775da750eb51351d5eb13e5ddfc9fcc315b1ab88c5f08d3e8977e2967b3a8ca5387f49bf2d0  lts.x86_64.config
712c5d19180de53f26b012529ee99d1fd1de9d1b769aa9c9f2be462db3a6c54e93429c8a0bc9389f2b447cbce7985952096ab8308438e4a7ad84103512e27929  virt.aarch64.config
c509a3bc4d649fcba33b6baba500ce384a04c9ab6e6ee83429d9d257f7d1406533146c4ac59409d51c0a68a0d1a8220654c4877a250ed7f2b57e6461dc6f846e  virt.armv7.config
a7a1af19b917c536b868e0108ba16b6cd2554b3bbac84ffa15cd8e9061d97499e64d7c4f713a98be54a56ce849f6c1e642d52a937be144ba63a360a8161d2be3  virt.ppc64le.config
ced1e1a39c6bba5073b806d5ae1c7c9fb11f95e9cb8e24e8c176de20c5dd2670cbbfa1d7be93f5ba5747620b6043f273bc5ff38acc29159a710ea49afb08fa25  virt.x86.config
4cf2f304371e67ece01b1d4d46ce82ccd56a920002f49cbbb507542aa8aec7f7744a37546bb638cdcd5d8611b760afb306ba5c89ec27efd71b8b61fbb76c1cac  virt.x86_64.config
205d165f16a95cd675dfb577906f12cbd40a0049cf2c83575a01eb9378146b10f86404d86552759597bb57f2272f74b0cb4098b896b8c2647cf759a59c47a30c  patch-6.1.58.xz
"
