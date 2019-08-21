#!/usr/bin/perl -w
# A simple Flattened Device Tree Blob (FDT/DTB) parser.
#
# Copyright (C) 2014 ARM Limited. All rights reserved.
#
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE.txt file.

use warnings;
use strict;
use integer;

package FDT;

# Tokens. These will appear (big endian) in the FDT stream.
use constant {
	FDT_BEGIN_NODE	=> 0x00000001,
	FDT_END_NODE	=> 0x00000002,
	FDT_PROP	=> 0x00000003,
	FDT_NOP		=> 0x00000004,
	FDT_END		=> 0x00000009,
};

use constant {
	CELL_SIZE	=> 4,
	TOK_SIZE	=> 4,
};

sub parse
{
	my $class = shift;
	my $fh = shift;
	my $self = bless {}, $class;

	my $header = FDT::Header->parse($fh) or goto failed;

	seek($fh, $header->{off_dt_struct}, 0);

	my $tree = FDT::Node->parse($fh, $header) or goto failed;

	$self->{header} = $header;
	$self->{tree} = $tree;

	return $self;

failed:
	warn("Unable to parse FDT");
	return undef;
}

# All tokens (32-bit) are must be naturally aligned, and any arbitrarily sized
# data must be padded with zeroes to 32-bit alignment. We swallow the padding
# here so as to not have to duplicate the logic elsewhere.
sub read_padded_data
{
	my $fh = shift;
	my $len = shift;
	my $off = tell($fh);
	read($fh, my $data, $len) == $len or goto failed;

	if ($len % FDT::TOK_SIZE != 0) {
		$len %= FDT::TOK_SIZE;
		seek $fh, (FDT::TOK_SIZE - $len), 1;
	}

	return $data;

failed:
	warn "Failed to read padded data";
	seek $fh, $off, 0;
	return undef;
}

sub skip_token
{
	my $fh = shift;
	my $expected = shift;
	my $curp = tell($fh);

	read($fh, my $rawtok, FDT::TOK_SIZE) == FDT::TOK_SIZE or goto failed;
	if (unpack("N", $rawtok) == $expected) {
		return $expected;
	}

failed:
	seek $fh, $curp, 0;
	return undef;
}

sub skip_nops
{
	my $fh = shift;
	while (defined(skip_token($fh, FDT::FDT_NOP))) {
		# do nothing
	}
}

sub get_root
{
	my $self = shift;
	return $self->{tree};
}

package FDT::Header;

use constant {
	MAGIC => 0xD00DFEED,
	LEN => 40,
};

sub parse
{
	my $class = shift;
	my $fh = shift;
	my $self = bless {}, $class;

	read($fh, my $raw_header, FDT::Header::LEN) == FDT::Header::LEN or goto failed;

	(
		$self->{magic},
		$self->{total_size},
		$self->{off_dt_struct},
		$self->{off_dt_strings},
		$self->{off_mem_rsvmap},
		$self->{version},
		$self->{last_comp_version},
		$self->{boot_cpuid_phys},
		$self->{size_dt_strings},
		$self->{size_dt_struct}
	) = unpack("NNNNNNNNNN", $raw_header);

	if ($self->{magic} != FDT::Header::MAGIC) {
		warn "DTB header magic not found";
		goto failed;
	}

	$self->read_strings($fh);

	return $self;

failed:
	warn "Unable to parse header";
	return undef;
}

sub read_strings
{
	my $self = shift;
	my $fh = shift;

	my $size = $self->{size_dt_strings};
	seek($fh, $self->{off_dt_strings}, 0);
	read($fh, $self->{strings}, $size) == $size or warn "Unable to read strings";
}

sub get_string
{
	my $self = shift;
	my $off = shift;
	return unpack("Z*", substr($self->{strings}, $off));
}

package FDT::Node;

sub parse_name
{
	my $fh = shift;
	my $curp = tell($fh);
	my $raw_name = "";
	my $name = "";

	do {
		read($fh, my $buf, FDT::TOK_SIZE) == FDT::TOK_SIZE or goto failed;
		$raw_name .= $buf;
		$name = unpack("A*", $raw_name);
	} while (length($raw_name) == length($name));

	return $name;

failed:
	warn "failed to read string";
	seek $fh, $curp, 0;
	return undef;
}

sub parse
{
	my $class = shift;
	my $fh = shift;
	my $header = shift;
	my $parent = shift;
	my $curp = tell($fh);

	FDT::skip_nops($fh);

	FDT::skip_token($fh, FDT::FDT_BEGIN_NODE) or goto failed;

	my $name = parse_name($fh);

	my $self = bless {}, $class;
	$self->{name} = $name;
	$self->{parent} = $parent;
	$self->{properties} = {};

	while (my $prop = FDT::Property->parse($fh, $header)) {
		$self->{properties}{$prop->{name}} = $prop;
	}

	my @children = ();
	my $child;

	for (;;) {
		$child = FDT::Node->parse($fh, $header, $self);
		last if (not defined($child));
		push (@children, $child);
	}

	$self->{children} = \@children;

	FDT::skip_token($fh, FDT::FDT_END_NODE) or goto failed;

	return $self;

failed:
	seek $fh, $curp, 0;
	return;
}

sub is_compatible
{
	my $self = shift;
	my $string = shift;

	my $compat_prop = $self->{properties}{"compatible"};
	return undef if (not defined($compat_prop));

	my @compatible = $compat_prop->read_strings();

	for my $compat (@compatible) {
		return $self if ($string eq $compat);
	}
}

sub find_compatible
{
	my $self = shift;
	my $string = shift;
	my @found = ();

	if ($self->is_compatible($string)) {
		push @found, $self;
	}

	for my $child (@{$self->{children}}) {
		push @found, $child->find_compatible($string);
	}

	return @found;
}

sub find_by_device_type
{
	my $self = shift;
	my $type = shift;
	my @found = ();

	my $selftype = $self->get_property("device_type");
	if (defined($selftype)) {
		if($selftype->read_string_idx(0) eq $type) {
			push @found, $self;
		}
	}

	for my $child (@{$self->{children}}) {
		push @found, $child->find_by_device_type($type);
	}

	return @found;
}

sub get_full_path
{
	my $self = shift;
	my $cur = $self;
	my @elems = ();

	# root node
	if (not defined($cur->{parent})) {
		return '/';
	}

	while (defined($cur->{parent})) {
		unshift @elems, $cur->{name};
		unshift @elems, '/';
		$cur = $cur->{parent};
	}
	return join ('', @elems);
}

sub get_property
{
	my $self = shift;
	my $name = shift;
	return $self->{properties}{$name};
}

sub get_num_reg_cells
{
	my $self = shift;

	my ($acp, $scp);
	my ($ac, $sc);

	$acp = $self->get_property("#address-cells");
	$scp = $self->get_property("#size-cells");

	return undef if (not defined($acp) && defined($scp));

	$ac = $acp->read_u32_idx(0);
	$sc = $scp->read_u32_idx(0);

	return ($ac, $sc);
}

sub translate_address
{
	my $self = shift;
	my $addr = shift;
	my $parent = $self->{parent};

	# root node require no translation
	return $addr if (not defined($parent));

	my $ranges = $self->get_property("ranges");
	if (not defined($ranges)) {
		warn ("Missing ranges on " . $self->{name} . ", idmap assumed");
		return $addr;
	}

	# An empty ranges property means idmap
	return $addr if ($ranges->{len} == 0);

	my ($ac, $sc) = $self->get_num_reg_cells();
	my ($pac, $psc) = $parent->get_num_reg_cells();

	if (not defined($ac) && defined($sc) && defined($pac) && defined($psc)) {
		warn "Missing #address-cells or #size-cells";
		return undef;
	}

	my $rc = $ac + $pac + $sc;

	if ($ranges->num_cells() % $rc != 0) {
		warn("Malformed ranges property");
		return undef;
	}

	for (my $off = 0; $off < $ranges->num_cells(); $off += $rc) {
		my ($cba, $pba, $len) = $ranges->read_cell_list($off, [$ac, $pac, $sc]);

		next if ($cba > $addr or $addr >= $cba + $len);

		return $addr - $cba + $pba;
	}

	warn "Did not find valid translation";
	return undef;
}

sub get_untranslated_reg
{
	my $self = shift;
	my $idx = shift;
	my $parent = $self->{parent};

	my ($ac, $sc) = $parent->get_num_reg_cells();
	my $reg = $self->get_property("reg");

	my $off = $idx * ($ac + $sc);

	return undef if ($off + $ac + $sc > $reg->num_cells());

	return $reg->read_cell_list($off, [$ac, $sc]);
}

sub get_translated_reg
{
	my $self = shift;
	my $idx = shift;
	my $parent = $self->{parent};

	my ($addr, $size) = $self->get_untranslated_reg($idx);

	return undef if (not defined($addr) && defined($size));

	for (my $parent = $self->{parent}; $parent; $parent = $parent->{parent}) {
		last if (not defined($addr));
		$addr = $parent->translate_address($addr);
	}

	return ($addr, $size);
}

package FDT::Property;

sub parse
{
	my $class = shift;
	my $fh = shift;
	my $header = shift;
	my $curp = tell($fh);

	my $self = bless {}, $class;

	FDT::skip_nops($fh);

	FDT::skip_token($fh, FDT::FDT_PROP) or goto failed;

	read ($fh, my $rawprop, 8) == 8 or goto failed;

	my ($len, $nameoff) = unpack("NN", $rawprop);
	$self->{name} = $header->get_string($nameoff);

	if ($len != 0) {
		$self->{data} = FDT::read_padded_data($fh, $len);
	}
	goto failed if ($len and not defined($self->{data}));

	$self->{len} = $len;

	return $self;

failed:
	seek $fh, $curp, 0;
	return undef
}

sub num_cells
{
	my $self = shift;
	return $self->{len} / FDT::CELL_SIZE;
}

sub read_cells_off
{
	my $self = shift;
	my $off = shift;
	my $cells = shift;
	my $fmt;

	# We only support u32 and u64 values
	if ($cells == 1) {
		$fmt = "N";
	} elsif ($cells == 2) {
		$fmt = "Q>";
	} else {
		return undef;
	}

	$off *= FDT::CELL_SIZE;
	my $raw = substr($self->{data}, $off);

	return unpack($fmt, $raw) if (defined($raw));
	return undef;
}

sub read_u32_idx
{
	my $self = shift;
	my $idx = shift;
	return $self->read_cells_off($idx, 1);
}

sub read_u64_idx
{
	my $self = shift;
	my $idx = shift;
	return $self->read_cells_off($idx * 2, 2);
}

sub read_cell_list
{
	my $self = shift;
	my $off = shift;
	my $cells = shift;

	my @ret;

	for (@{$cells}) {
		my $val = $self->read_cells_off($off, $_);
		push @ret, ($val);
		$off += $_;
	}

	return @ret;
}

sub read_strings
{
	my $self = shift;
	return split('\0', $self->{data});
}

sub read_string_idx
{
	my $self = shift;
	my $idx = shift;
	my @strings = $self->read_strings();
	return $strings[$idx];
}

1;
