#!/bin/bash

phpver=$(php --version | head -n1 | cut -d' ' -f2 | cut -d'.' -f1-2)
if [ "$phpver" == "5.6" ] || [ "$phpver" == "7.0" ] ; then
  echo "Found PHP Version $phpver, stripping incompatible reference implementation dependencies"
  composer remove --dev nyholm/psr7 nyholm/psr7-server riswallsmith/buzz endframework/zend-httphandlerrunner
  fi
