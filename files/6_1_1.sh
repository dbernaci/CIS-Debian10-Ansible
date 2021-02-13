#!/bin/bash
listOfPackages=($(dpkg -l | sed 1,5d | awk '{print $2}' | paste -s))
for package in "${listOfPackages[@]}"; do
    outdpkg=$(dpkg --verify ${package})
    if [ "$outdpkg" != "" ] ; then
        echo "Package '${package}':"
        echo "${outdpkg}"
    fi
done
