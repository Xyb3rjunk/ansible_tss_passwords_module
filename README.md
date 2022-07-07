# tss_passwords - A Thycotic Secret Server Ansible Module
********** Work in progress - untested due to lack of testing environment. In early stages of development and not ready for use! **********
Parts of this module may still be in pseudo code at time of push.
## Overview
An Ansible module which uses Thycotic's Secret Server API to generate and update stored passwords. More specifically, it can update or search for an entry, generate API tokens, generate passwords and test the API connectivity.
The name and description of options has been designed to replicate the community tss_lookup module where practical.

## Usage
Full usage is documented in Ansible module compliant formatting.
The behaviour of the module is selected with the "action" option. This takes the arguments "search", "update", "generate_token", "generate_password" and "test_api". This defaults to "search" soas to avoid accidental overwrites.

## Notes
### Options
#### Option Names
The TSS return values key_name and value_name have been included as aliases to the more useful terms "secret_folder" and "secret_user" (assumed meaning - original not well documented)
