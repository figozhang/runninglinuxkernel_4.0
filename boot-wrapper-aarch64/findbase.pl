#!/usr/bin/perl -w
# Find device register base addresses.
#
# Usage: ./$0 <DTB> <index> <compatible ...>
#
# Copyright (C) 2014 ARM Limited. All rights reserved.
#
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE.txt file.

use warnings;
use strict;

use FDT;

my $filename = shift;
die("No filename provided") unless defined($filename);

my $idx = shift;
die("no reg index provided") unless defined($idx);

my @compats = shift;

open (my $fh, "<:raw", $filename) or die("Unable to open file '$filename'");

my $fdt = FDT->parse($fh) or die("Unable to parse DTB");

my $root = $fdt->get_root();

my @devs = ();
for my $compat (@compats) {
	push @devs, $root->find_compatible($compat);
}

# We only care about finding the first matching device
my $dev = shift @devs;
die("No matching devices found") if (not defined($dev));

my ($addr, $size) = $dev->get_translated_reg($idx);
die("Cannot find reg entry $idx") if (not defined($addr) or not defined($size));

printf("0x%016x\n", $addr);
