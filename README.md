# udooneo-m4uploader

Package for NEO M4 firmware local uploading.  
It consist in two parts:
 - **mqx_upload_on_m4SoloX** : backend C uploader, written in C
 - **udooneo-m4uploader** : frontend bash script, copy last firmware

## Install

    $ make 
    # make install

## Debian package

    $ debuild -uc -us
    # dpkg -i ../*.deb

## Usage

    udooneo-m4uploader [option] fw_filename.bin

    UDOO Neo MQX Uploader Frontend
    Options:
      -r,--reset  Reset M4, simply reloading last sketch
      -v          Verbose output
      --version   Show version

