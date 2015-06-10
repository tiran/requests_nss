#!/bin/sh

DBDIR=pki
DB=sql:$DBDIR

if [ ! -d $DBDIR ]; then
    mkdir $DBDIR
    # create NSS DB
    modutil -force -dbdir $DB -create
    # add root CA provider
    modutil -force -dbdir $DB -add ca_certs -libfile /etc/alternatives/libnssckbi.so.x86_64
fi

modutil -dbdir $DB -list
certutil -d $DB -L -h all

