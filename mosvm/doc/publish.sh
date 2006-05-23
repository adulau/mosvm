#!/bin/sh
gmake
scp *.html *.css *.pdf mosquito@marathon:/var/www/mosquito.merseine.nu/vmdesign
scp *.pdf sdunlop@inferno:.
