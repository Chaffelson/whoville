#!/bin/bash

#remount tmpfs to ensure NOEXEC is disabled
mount -t tmpfs -o exec tmpfs /tmp
