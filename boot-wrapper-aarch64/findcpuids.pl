#!/usr/bin/perl -w
# Find CPU IDs
#
# Usage: ./$0 <DTB>
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

open (my $fh, "<:raw", $filename) or die("Unable to open file '$filename'");

my $fdt = FDT->parse($fh) or die("Unable to parse DTB");

my $root = $fdt->get_root();

my @cpus = $root->find_by_device_type('cpu');

my @ids = map {
	my ($addr, $size) = $_->get_untranslated_reg(0);
	sprintf("0x%x", $addr);
} @cpus;

printf("%s\n", join(',', @ids));
