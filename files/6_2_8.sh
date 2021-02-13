#!/bin/bash
>/tmp/.6.2.8
grep -E -v '^(halt|sync|shutdown)' /etc/passwd | awk -F: '($7 != "'"$(which nologin)"'" && $7 != "/bin/false") { print $1 " " $6 }' | while read user dir; do
    if [ ! -d "$dir" ]; then
        echo "The home directory ($dir) of user $user does not exist."
    else
        dirperm=$(ls -ld $dir | cut -f1 -d" ")
        if [ $(echo $dirperm | cut -c6) != "-" ]; then
            echo "$dir" >/tmp/.6.2.8
        fi
        if [ $(echo $dirperm | cut -c8) != "-" ]; then
            echo "$dir" >>/tmp/.6.2.8
        fi
        if [ $(echo $dirperm | cut -c9) != "-" ]; then
            echo "$dir" >>/tmp/.6.2.8
        fi
        if [ $(echo $dirperm | cut -c10) != "-" ]; then
            echo "$dir" >>/tmp/.6.2.8
        fi
    fi
    cat /tmp/.6.2.8 | sort -n | uniq
done
