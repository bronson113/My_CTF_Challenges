#!/bin/sh

su gleamering_star -c 'cd /var/gleamering/gleamering_star && gleam run'&
su gleamering_light -c 'cd /var/gleamering/gleamering_light && gleam run'


