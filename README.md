# tpm-luks

## What is this about?
Have you ever wondered how does Windows Bitlocker-protected computers start without entering password during boot? While this is only one of the possible Bitlocker configurations (and certainly not the most secure one), it is very user, friendlthe and provides certain level of security. (if the storage root key and computer state in PCRs match the expectation defineds during the sealing process) or unsealing fails (if a system state has been tampered with). When the unsealing process fails, your 

Windows uses the so-called Trusted Platform Module (TPM) to provide Bitlocker encryption without entering password on boot.
As the Bitlocker component is configured when Windows is up and running, when the TPM is present in the system, it is initialized and desired state of boot is precomputed by the operating system. Bitlocker secret is then bound (sealed) to this precomputed state and stored on the boot drive (a TPM storage root key is used in this process; TPM itself is the component which does the sealing).

During boot, each component which is part of the boot process gets measured (hashed) and the measurement is then extended into TPM Platform Control Registers (PCRs). This includes your BIOS/UEFI code, some data (such as current state of your partitions in MBR or GPT), operating system boot loader, kernel and its start-up parameters (such as "is safe mode enabled?"). Based on these measurements, the Windows secret is either unsealed by the TPM (if the storage root key and computer state in PCRs match the expectations defined during the sealing process) or unsealing fails (if a system state has been tampered with). When the unsealing process fails, Windows prompt user for the Bitlocker recovery password.

In Linux, the support of TPM has existed for years in kernel, but there is very limited support in bootloaders and toolchain to allow similar set-up for LUKS-encrypted root filesystem drives. There are the following projects regarding Measured boot and LUKS-TPM in Linux:
* [TrustedGrub](https://projects.sirrix.com/trac/trustedgrub/) - fails to compile on up-to-date distros
* [TrustedGrub2](https://github.com/Rohde-Schwarz-Cybersecurity/TrustedGRUB2) - has to be compiled manually, prints errors on boot, lacks support for UEFI and does not measure kernel commandline separately (only as part of commands executed from grub.cfg), halts the system on TPM absence
* [Grub2 with TPM support by Matthew Garrett](https://github.com/mjg59/grub) - has support for TPM1.2 and TPM 2.0, UEFI, but does not fully fit the Ubuntu environment (PCR[10] is used for IMA in Ubuntu, therefore cannot be used for tpm-luks without complex work-arounds; mixes PCRs for different uses and makes PCR precomputation difficult)
* [tpm-luks by Kent Yoder](https://github.com/shpedoikal/tpm-luks) - expects boot via TrustedGRUB, lack support of Grub2, supports initramfs generation for old Fedoras only
* [shim with TPM support by Matthew Garrett](https://github.com/mjg59/shim/commits/tpm) - introduces support for TPM into the shim bootloader.
 
While there were multitude options to choose from, none of them matched the feature set needed for Ubuntu support, namely:
* be predictable, so that the PCR state can be precomputed programatically
* be compilable by Launchpad on latest Ubuntu distributions
* support Grub2 as much as possible
* on initrd update and/or kernel installation, automagically precompute and store LUKS secret into new slot of NVRAM to facilitate password-less boot with the newly installed components
* provide support for UEFI-based boot when SHIM is used as well as when SHIM is not used (Grub is loaded by UEFI directly)
 
As a result, the tools to facilitate the feature set above are included in this repository, together with the [Grub2-tpm for Ubuntu](https://github.com/zajdee/ubuntu1704-grub-tpm) repository. These repositories are accompanied by a [LUKS-TPM Launchpad PPA](https://launchpad.net/~radek-zajic/+archive/ubuntu/measuredluks), where the precompiled packages are available for easy installation.

## How to use this toolset

### Install ubuntu with encrypted rootfs, update and upgrade

`sudo apt update && sudo apt dist-upgrade`

### Add PPA with grub-tpm and tpm-luks prebuilt
A prebuilt repository of Ubuntu DEB packages is available.

`sudo apt-add-repository ppa:radek-zajic/measuredluks`

### Update again
This will install grub with support for measured boot.

`sudo apt update && sudo apt dist-upgrade`

### Install tpm-luks
This step installs toolset from this repository.

`sudo apt install tpm-luks`

### Configure tpm-luks
Into `/etc/tpm-luks.conf` add the following line:

`LUKS_INITRD_ENABLE=1`

Then configure `DEVICE="/dev/sdXY"` e.g. /dev/sdf3 where sdXY is your encrypted rootfs

Next, passwords must be configured.

1. if multibooting with other tpm-luks secured system: 
 * edit `/etc/tpm-luks.conf` and copy&paste `OWNERPASS` & `NVPASS` from the other tpm-luks secured system
2. if multibooting with Windows using Bitlocker or Drive encryption
 * sorry, **unless you get the owner password from your Windows installation, this combination does not work!**
3. if this is your only TPM-secured system on that computer
 * Go to BIOS, clear your TPM and reboot
 * Go to BIOS again, enable your TPM and boot into tpm-luks secured system
 * in `/etc/tpm-luks.conf` set your `OWNERPASS` and `NVPASS` passwords 
    * do not use the same pw for both as NVPASS gets copied into initramdisk!
    * for your convenience, you can use the password generator at https://www.random.org/passwords/?num=1&len=8&format=html&rnd=new
4. optional (for UEFI boot): if you are not using secure boot, you can adjust boot order after installation, e.g.
```
    efibootmgr -v  # lists boot entries
    efibootmgr -o 9,8,0  # change boot order to entries 9, 8, 0
```

### Edit grub defaults in `/etc/default/grub`
Remove the `splash` keyword from `GRUB_KERNEL_CMDLINE`
 * This is necessary to properly measure kernel cmdline, no variables are allowed. The splash keywords adds a `$vt_handoff` variable, which breaks the precomputation script.

Add `panic=60` to your kernel cmdline, otherwise your LUKS-TPM set-up is exploitable and LUKS password can be easily stolen!

Optional: if you want to start multiple entries from grub, please change savedefault parameters
```
     GRUB_DEFAULT=saved
     GRUB_SAVEDEFAULT=true
```

### Regenerate grub config file and reinstall grub
```
    sudo update-grub
    sudo grub-install /dev/sdX # where X is your boot drive letter
```

### Reboot into desired state
This is to ensure PCRs will be precomputed properly (useful mainly if you are using PCR[8] or PCR[11] for seaing, which cannot be precomputed as of now).

### Update initramfs
This step adds necessary code for TPM unlocking to your initramfs.
`sudo update-initramfs -k all -u`

### Initialize tpm-luks
In this step, the scripts add a new LUKS key to your LUKS-protected drive, then store this key into TPM NVRAM. Passwords and PCR states assured by steps above are used to seal this password to *only* allow access to the NVRAM, if NVRAM password is known and PCR state matches. In other cases, access to the NVRAM is disallowed.
`sudo tpm-luks-init`

### Test by rebooting your machine
Your PC should boot without entering LUKS password now!

### Further harden your system:
  * disable Guest log-in
 http://ubuntuhandbook.org/index.php/2016/04/remove-guest-session-ubuntu-16-04/
  * set permissions for tpm_nvread to root-only so that users can't read your NVRAM password
`sudo chmod 0700 /usr/sbin/tpm_nvread`
