#!/usr/bin/env bash

#remount tmpfs to ensure NOEXEC is disabled
mount -o remount,size=10G /tmp
mount -o remount,exec /tmp

