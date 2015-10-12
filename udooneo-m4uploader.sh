#!/bin/bash


if [[ $# -lt 1 ]]
   then
     echo
     echo "   Usage:  $0   fw_filename.bin"
     echo
     exit 0
fi

/usr/bin/mqx_upload_on_m4SoloX /usr/share/arduino/lib/clean.fw

/usr/bin/mqx_upload_on_m4SoloX $1
