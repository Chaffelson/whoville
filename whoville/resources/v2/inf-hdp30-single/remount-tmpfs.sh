#!/usr/bin/env bash

#remount tmpfs to ensure NOEXEC is disabled
if grep -Eq '^[^ ]+ /tmp [^ ]+ ([^ ]*,)?noexec[, ]' /proc/mounts; then
  echo "/tmp found as noexec, remounting..."
  mount -o remount,size=10G /tmp
  mount -o remount,exec /tmp
else
  echo "/tmp not found as noexec, skipping..."
fi

