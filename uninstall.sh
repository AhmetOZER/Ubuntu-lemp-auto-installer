#!/bin.bash
rm mysql.parola
apt autoremove --purge mysql* php* nginx* -y
rm -rf /tmp/phpmyadmin
rm -rf /etc/nginx
rm -rf /etc/ahmetozerlamp
rm -rf /etc/php*
rm -rf /web
