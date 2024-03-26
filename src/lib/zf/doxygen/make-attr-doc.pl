#!/usr/bin/perl
#
# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: (c) 2016 Advanced Micro Devices, Inc.

use strict;
use warnings;

use FindBin qw($Bin);

sub destringify
{
  my $str = $_[0];

  # Remove adjacent quotes, with any intervening space, in pairs.
  $str =~ s/(?<!\\)"\s*"//g;

  # Remove first and last quotes.
  $str =~ s/\s*(?<!\\)"//g;

  return $str;
}


# Generate a Doxygen comment giving a link to the attribute reference.
sub doxygen_attr_link
{
  my ($name) = @_;

  # Return the comment.
  return "\\attrlink{$name}\n";
}


# Generate a Doxygen comment giving a reference description for an attribute.
sub doxygen_attr_comment
{
  my ($type, $name, $default, $default_desc, $components, $description) = @_;
  my %friendly_types = (
    'str'     => 'String',
    'int'     => 'Integer',
    'bitmask' => 'Bitmask',
  );

  # Remove quotes.
  $_ = destringify($_)
    foreach( $default, $default_desc, $components, $description );

  # Make the component list easier to read.
  $components =~ s/,/, /g;

  # Fall back to the numeric default if no description is given for it.
  $default_desc = $default if( $default_desc eq 'NULL' );

  # Split the description after the first sentence
  my ($brief_description, $extra_description);
  unless( ($brief_description, $extra_description)
      = ($description =~ /^(.+?\.(?<!\w\.\w\.))\s+(.+)$/) ) {
    $brief_description = $description;
    $extra_description = "";
  }

  # Return the comment.
  return <<EOC
/**
 * \\attr{$name}
 *
 * \\brief $brief_description
 *
 * \\attrdetails
 *   $extra_description
 *
 * \\attrtype
 *   $friendly_types{$type}.
 *
 * \\attrdefault
 *   $default_desc.
 *
 * \\attrrelevant
 *   $components.
 */
EOC
}


### main()

# Patterns for matching C strings.  These are from C::Tokenize, but rather than
# introduce another dependency, we copy them here.

my $single_string_re = qr/
                             (?:
                                 "
                                 (?:[^\\"]+|\\[^"]|\\")*
                                 "
                             )
                         /x;

my $string_re = qr/$single_string_re(?:\s*$single_string_re)*/;


# Patterns to match ZF_ATTR() macros.
my $comma_re = qr/\s*,\s*/;
my $zf_attr_re = qr/
                      ZF_ATTR[(]
                        \s*
                          (str|int|bitmask)
                        $comma_re
                          (\w+)
                        $comma_re
                          # Only document stable attributes.
                          stable
                        $comma_re
                          # This must be an integer or NULL, so not-a-comma is
                          # good enough.
                          ([^,]*)
                        $comma_re
                          ($string_re|NULL)
                        $comma_re
                          ($string_re)
                        $comma_re
                          ($string_re)
                        \s*
                      [)]
                   /x;

# Slurp the whole of attr_tmpl.h.
my $source_file = "$Bin/../../../include/zf_internal/attr_tmpl.h";
my $source;
{
  # Group this, to localize the change to the Input Record Separator
  open my $fh, '<', $source_file or die;
  local $/ = undef;
  $source = <$fh>;
  close $fh;
}
# Extract the Doxygen comments and the links to them from the ZF_ATTR macros
my %links;
my %comments;
while( $source =~ /$zf_attr_re/g ) {
  my ($type, $name, $default, $default_desc, $components, $description) =
    ($1, $2, $3, $4, $5, $6);
  $links{$name} = doxygen_attr_link($name);
  $comments{$name} = doxygen_attr_comment($type, $name, $default,
                                          $default_desc, $components,
                                          $description);
}


# Filter the original attributes file, replacing the <placeholder> lines.
while( <> ) {
  if( /^<placeholder for generated attrlinks>$/ ) {
    # Output the links, sorted by attribute name.
    print $links{$_} for( sort(keys(%links)) );
  }
  elsif ( /^<placeholder for generated reference pages>$/ ) {
    # Output the comments, sorted by attribute name.
    print $comments{$_} for( sort(keys(%comments)) );
  }
  else {
    print;
  }
}
