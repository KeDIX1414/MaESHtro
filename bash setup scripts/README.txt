Installing the portDropping script

    Option 1 (preferred):
        - on the GATEWAY pi, copy portDropping.sh into: ~/etc/init.d
        - make it executable: $ chmod +x /etc/ini.t/portDropping.sh
        - update the boot sequence: $ sudo update-rc.d /etc/init.d/portDropping.sh defaults

    Option 2:
        - run  $ sudo crontab -e
        - then $ @reboot /path/to/portDropping.sh

grabMyIP.sh
-- this may be a bit overkill, but we can use this to grab the ip address of the
given interface (can call the script from within gateway c code)
-- alternative is to write C code that essentially does the same thing
-- if using this make sure to make it executable! ($chmod +x /path/to/grabMyIP.sh)
