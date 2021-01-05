#!/usr/bin/env perl

use strict;
use warnings;
use File::Spec;

my $defines = {};
my $includes = {};
my @includes_order = ();
my @stack;

sub slurpfile {
    my $filename = shift;
    my $parent = shift;
    if(!defined($parent)) {
        $parent = '';
    }
    open(my $fh, '<', $filename) or die "File $parent failed to include $filename: $!";
    my @lines = <$fh>;
    close($fh);
    return @lines;
}

sub processfile {
    my $filename = shift;
    my $parent = shift;
    my @lines = @_;
    my $output = '';

    my $start = 0;
    my $end = $#lines;

    if(defined($parent)) {
        push(@stack,"$parent => $filename");
    } else {
        push(@stack,$filename);
    }

    # check for ifndef-guard
    my ($def1) = ( $lines[0] =~ /^#ifndef\s+(.+)$/);
    if(defined($def1)) {
        chomp($def1);
        my ($def2) = ( $lines[1] =~ m/^#define\s+(.+)$/);
        if(defined($def2)) {
            chomp($def2);

            if($def1 eq $def2) {
                if(exists($defines->{$def1})) {
                    return '';
                }
                else {
                    $defines->{$def1} = 1;
                    $start = 2;
                    while($lines[$end] !~ m/^#endif/) {
                        $end--;
                    }
                    $end--;
                }
            }
        }
    }

    #my $stack_info = "#if 0\nBEGIN $filename\nSTACK\n";
    #foreach my $filename (@stack) {
    #    $stack_info .= "$filename\n";
    #}
    #$stack_info .= "#endif\n\n";

    #$output .= $stack_info;

    foreach my $i ($start..$end) {
        $output .= processline($filename,$lines[$i], $i + 1);
    }


    pop(@stack);

    return $output;
}

sub processline {
    my $filename = shift;
    my $line = shift;
    my $linenum = shift;

    if($line =~ /^#include\s+</) {
        my ($includename) = ($line =~ /^#include\s+<([^>]+)>/);
        if(not exists($includes->{$includename})) {
            push(@includes_order,$includename);
            $includes->{$includename} = 1;
        }
        return '';
    }

    if($line !~ /^#include\s+"/) {
        return $line;
    }

    my ($volume, $dir, $file) = File::Spec->splitpath($filename);
    $dir = $volume . $dir;
    my ($newfile) = ( $line =~ /^#include\s+"([^"]+)"/);
    $newfile = File::Spec->catfile($dir,$newfile);

    my @lines = slurpfile($newfile,$filename);
    return processfile($newfile,$filename.'[' . $linenum . ']',@lines);
}

if(@ARGV < 1) {
    print STDERR "Usage: amalage.pl /path/to/source.c ..\n";
    exit(1);
}

my $output = <<'EOF';
/* this file is automatically generated */
EOF

foreach my $file (@ARGV) {
    @stack = ();
    my @lines = slurpfile($file,'');
    $output .= processfile($file,undef,@lines);
}

my $inc = '';
foreach my $i (@includes_order) {
    $inc .= '#include <' . $i . ">\n";
}

print $inc;
print $output;