Scriplets monitor
=================

Produce data about the scriptlets within the installed rpms for the system.

 * go build
 * docker run -v $(pwd):/mnt fedora:29 bash
 * /mnt/scriplets-monitor /mnt/pkgs-f29

You'll then get:

 * /mnt/pkgs-f29.name - csv file of package names and scriptlet data.
 * /mnt/pkgs-f29.nevra - csv file of package nevras and scriptlet data.
 * /mnt/pkgs-f29.d/* - package scriptlets as /NEVRA.TYPE

You can then diff the .name files between runs/versions to see what is changing.
