#!/bin/sh
set -eu
nginx -t
nginx -s reload
