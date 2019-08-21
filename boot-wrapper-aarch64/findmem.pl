#!/usr/bin/perl -w
# Find the start of physical memory
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

# We assume the memory nodes and their reg entries are ordered by address.
my @mems = $root->find_by_device_type("memory");
my $mem = shift @mems;
die("Unable to find memory") unless defined($mem);

my ($addr, $size) = $mem->get_translated_reg(0);
die("Cannot find first memory bank") unless (defined($addr) && defined($size));

printf("0x%016x\n", $addr);
