
= build pre-reqs =

 Packages: automake, autoconf, libtool, gcc, libssl-dev, gnu-efi, libmd-dev, make, build-essential

= build steps =

 $ autoreconf -ivf
 $ ./configure
 $ make
 # make install

= runtime pre-reqs =

 For using tpm-luks with a LUKS key on your rootfs volume: initramfs-tools grub2*

 All uses: coreutils tpm-tools-1.3.8 trousers-0.3.9 binutils mawk efibootmgr grep util-linux sed bash cryptsetup-bin grub-common

 tpm-luks requires very recent tpm-tools and trousers versions, likely not
included in your distro. To get these versions, you'll need to install them
from their upstream repositories:

 $ git clone git://trousers.git.sourceforge.net/gitroot/trousers/trousers trousers.git
 $ git clone git://trousers.git.sourceforge.net/gitroot/trousers/tpm-tools tpm-tools.git
 $ cd trousers.git
 $ sh bootstrap.sh
 $ ./configure
 $ make
 # make install
 $ cd ../tpm-tools.git
 $ sh bootstrap.sh
 $ ./configure
 $ make
 # make install

EOF
