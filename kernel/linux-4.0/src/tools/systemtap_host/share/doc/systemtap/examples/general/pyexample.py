#!/usr/bin/python
# Copyright (C) 2014 Red Hat, Inc.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as
# published by the Free Software Foundation.

import sys

aglobal9 = 9

def celsius_to_farenheit(celsius):
    atuple = "a", "b", "c"
    alist = [1, 2, 3]
    aset = set([1, 2, 3])
    adict = { 1 : "a", 2 : "b", 3 : "c" }

    nine = aglobal9
    five = 5
    thirty_two = 32
    i = 1
    return str((nine * celsius) / five + thirty_two)

def main():
    if (len(sys.argv) < 2):
        print ("Usage: " + sys.argv[0] + " Temp")
        return 1

    celsius = int(sys.argv[1])
    print (str(celsius) + " Celsius " + " is " + celsius_to_farenheit(celsius) + " Farenheit")
    return 0

if __name__ == "__main__":
    sys.exit(main())
