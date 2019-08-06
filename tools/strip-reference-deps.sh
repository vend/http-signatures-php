#!/bin/sh

phpver=$(php --version | head -n1 | cut -d' ' -f2 | cut -d'.' -f1-2)
if [ "$phpver" == "5.6" ] || [ "$phpver" == "7.0" ] ; then
  composer remove --dev nyholm/psr7 nyholm/psr7-server riswallsmith/buzz endframework/zend-httphandlerrunner
  fi
