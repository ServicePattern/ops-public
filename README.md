# ops-public

Bright Pattern's Operations public resources. Please reade a code befor use.

Before use:
1. Please update ansible/roles/defaults/main.yml
1. Please test using ansible/roles/vars/test.yml
1. Enable periodic schedule `/etc/cron.d/logstorage` and `/etc/cron.d/coldstorage`,
1. Change schedule if necessary.

Refer to ansible manual to apply playboor to your monitoring hosts.

**Note:** scripts are using python 2.7