#!/usr/bin/env bash

#remount tmpfs to ensure NOEXEC is disabled
if grep -Fxq "/etc/fstab" /tmp
then
    mount -o remount,size=10G /tmp
    mount -o remount,exec /tmp
fi