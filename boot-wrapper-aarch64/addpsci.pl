#!/usr/bin/perl -w
# Generate additions to add a PSCI enable-method to cpu nodes.
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

foreach my $cpu (@cpus) {
	printf("&{%s} { enable-method = \\\"psci\\\"; };\n", $cpu->get_full_path());
}
