#!/bin/bash
set -euo pipefail
umask 077

backup_dir=/opt/rajacek/backups
mkdir -p "$backup_dir"
chmod 700 "$backup_dir"
stamp=$(date +%Y%m%d-%H%M%S)
final="$backup_dir/rajacek-$stamp.sql.gz"
partial="$final.partial"
trap 'rm -f -- "$partial"' EXIT

docker exec rajacek-mysql8 sh -c \
  'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" exec mysqldump -uroot --single-transaction --quick --routines --triggers --events rajacek' \
  | gzip -1 > "$partial"
gzip -t "$partial"
test -s "$partial"
mv -- "$partial" "$final"
trap - EXIT
find "$backup_dir" -maxdepth 1 -type f -name 'rajacek-*.sql.gz' -mtime +30 -delete
printf 'backup_ok=%s\n' "$final"
