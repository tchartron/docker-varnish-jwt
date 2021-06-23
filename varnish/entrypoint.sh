#!/bin/bash

# mkdir -p /var/lib/varnish/`hostname` && chown nobody /var/lib/varnish/`hostname`
/usr/sbin/varnishd -s malloc,128M -a :80 -f /etc/varnish/default.vcl

/usr/bin/varnishncsa -F '%{Host}i %h %l %u %t \"%r\" %s %b \"%{Referer}i\" \"%{User-agent}i\" \"%{Varnish:hitmiss}x\"'
