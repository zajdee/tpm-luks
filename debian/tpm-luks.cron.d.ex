#
# Regular cron jobs for the tpm-luks package
#
0 4	* * *	root	[ -x /usr/bin/tpm-luks_maintenance ] && /usr/bin/tpm-luks_maintenance
