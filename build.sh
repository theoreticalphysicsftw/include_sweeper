#!/bin/bash
if [ "$1" == "--debug" ] 
then
    echo "Debug build..."
    gcc -Wall -Wextra -pedantic -g -nostdlib -nostartfiles -static -o build/include_sweeper include_sweeper.c
else
    echo "Release build..."
    gcc -Os -nostdlib -nostartfiles -nodefaultlibs -static -fno-asynchronous-unwind-tables -s -o build/include_sweeper include_sweeper.c
    strip --remove-section .note.gnu.build-id --remove-section .comment build/include_sweeper
fi
