define(`r_file_perms', `{ getattr open read }')
define(`allow_read', `allow $1 $2:file r_file_perms;')
