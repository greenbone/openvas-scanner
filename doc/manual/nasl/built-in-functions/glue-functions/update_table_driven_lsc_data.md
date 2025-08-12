# update_table_driven_lsc_data

## NAME

**update_table_driven_lsc_data** - Set information, so that openvas can start a table driven lsc

## SYNOPSIS

*void* **update_table_driven_lsc_data**(pkg_list: *str*, os_release: *str*);

**update_table_driven_lsc_data** two named arguments

## DESCRIPTION

This function sets internal KB items *ssh/login/package_list_notus* and *ssh/login/release_notus* withe the given arguments:
pkg_list: comma separated list of installed packages of the target system
os_release: identifier for the operating system of the target system

After the KB items are set, these information is also transferred to the main process and a notus scan is triggered. The
results of the notus scan are then directly published.

## RETURN VALUE

This function returns nothing.

## SEE ALSO

**[log_message(3)](log_message.md)**