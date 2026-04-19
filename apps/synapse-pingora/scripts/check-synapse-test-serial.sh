#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CALLER_PWD="$PWD"

cd "$ROOT"

CALLER_PWD="$CALLER_PWD" perl - "$ROOT" "$@" <<'PERL'
use strict;
use warnings;
use Cwd qw(abs_path getcwd);
use File::Find;
use File::Spec;

my ($root, @targets) = @ARGV;
my $cwd = $ENV{CALLER_PWD} // getcwd();

my @files;
if (@targets) {
    for my $target (@targets) {
        my $path = File::Spec->file_name_is_absolute($target)
            ? $target
            : File::Spec->catfile($cwd, $target);
        my $resolved = abs_path($path)
            or die "failed to resolve $target from $cwd\n";
        unless ($resolved =~ /\.rs$/ && index($resolved, "$root/") == 0) {
            warn "skipping non-Rust or out-of-tree target: $target\n";
            next;
        }
        push @files, $resolved;
    }
} else {
    find(
        sub {
            return unless -f $_ && $_ =~ /\.rs$/;
            return unless $File::Find::name =~ m{/(?:src|tests)/};
            return if $File::Find::name =~ m{/target/};
            push @files, abs_path($File::Find::name);
        },
        $root,
    );
}

# Sort for deterministic, reproducible audit output across filesystems.
@files = sort @files;

my $hit_re = qr{
    \bSYNAPSE\b
  | DetectionEngine::\w+\s*\(
  | (?:self|proxy)\.(?:request_filter|early_request_filter|request_body_filter|upstream_request_filter)\s*\(
  | SynapseProxy::(?:with_health|new|with_entity_config)\s*\(
}x;

my @missing;
my $audited = 0;

sub is_test_attr {
    my ($attr) = @_;
    return $attr =~ /^#\[(?:tokio::|async_std::|test_log::)?test\b/m
        || $attr =~ /cfg_attr\([^\)]*\b(?:tokio::|async_std::|test_log::)?test\b/m
        || $attr =~ /^#\[(?:rstest|rstest::rstest)\b/m;
}

sub is_serial_attr {
    my ($attr) = @_;
    return $attr =~ /^#\[(?:serial|serial_test::serial)\b/m;
}

sub strip_line_for_scan {
    my ($line, $state) = @_;
    my $out = '';
    my $i = 0;
    my $len = length $line;

    while ($i < $len) {
        if ($state->{mode} eq 'block_comment') {
            if ($i + 1 < $len && substr($line, $i, 2) eq '/*') {
                $state->{block_depth}++;
                $i += 2;
                next;
            }
            if ($i + 1 < $len && substr($line, $i, 2) eq '*/') {
                $state->{block_depth}--;
                $i += 2;
                if ($state->{block_depth} <= 0) {
                    $state->{mode} = 'normal';
                    $state->{block_depth} = 0;
                }
                next;
            }
            $i++;
            next;
        }

        if ($state->{mode} eq 'string' || $state->{mode} eq 'char') {
            my $delim = $state->{mode} eq 'string' ? '"' : "'";
            my $ch = substr($line, $i, 1);
            if ($state->{escape}) {
                $state->{escape} = 0;
            } elsif ($ch eq '\\') {
                $state->{escape} = 1;
            } elsif ($ch eq $delim) {
                $state->{mode} = 'normal';
            }
            $i++;
            next;
        }

        if ($state->{mode} eq 'raw') {
            my $delimiter = '"' . ('#' x $state->{raw_hashes});
            if (substr($line, $i, length($delimiter)) eq $delimiter) {
                $state->{mode} = 'normal';
                $state->{raw_hashes} = 0;
                $i += length($delimiter);
                next;
            }
            $i++;
            next;
        }

        if ($i + 1 < $len && substr($line, $i, 2) eq '//') {
            last;
        }

        if ($i + 1 < $len && substr($line, $i, 2) eq '/*') {
            $state->{mode} = 'block_comment';
            $state->{block_depth} = 1;
            $i += 2;
            next;
        }

        if (substr($line, $i) =~ /\Ar(#+)?"/) {
            $state->{mode} = 'raw';
            $state->{raw_hashes} = defined $1 ? length($1) : 0;
            $i += length($&);
            next;
        }

        my $ch = substr($line, $i, 1);
        if ($ch eq '"') {
            $state->{mode} = 'string';
            $state->{escape} = 0;
            $i++;
            next;
        }

        if ($ch eq "'") {
            $state->{mode} = 'char';
            $state->{escape} = 0;
            $i++;
            next;
        }

        $out .= $ch;
        $i++;
    }

    return $out;
}

for my $file (@files) {
    open my $fh, '<', $file or die "failed to read $file: $!";
    local $/;
    my $content = <$fh>;
    close $fh;

    my @lines = split /\n/, $content, -1;
    my @functions;
    my @attrs;
    my $attr_buffer = undef;

    for (my $i = 0; $i <= $#lines; $i++) {
        (my $trim = $lines[$i]) =~ s/^\s+|\s+$//g;

        if (defined $attr_buffer) {
            $attr_buffer .= "\n$trim";
            if ($trim =~ /\]$/) {
                push @attrs, $attr_buffer;
                $attr_buffer = undef;
            }
            next;
        }

        if ($trim =~ /^#\[/) {
            if ($trim =~ /\]$/) {
                push @attrs, $trim;
            } else {
                $attr_buffer = $trim;
            }
            next;
        }

        if ($trim eq '' || $trim =~ m{^(?://|/\*|\*/|\*)} || $trim =~ m{^//!?} || $trim =~ m{^///}) {
            next;
        }

        if ($trim =~ /^(?:pub(?:\([^)]+\))?\s+)?(?:async\s+)?fn\s+([A-Za-z0-9_]+)\s*\(/) {
            push @functions, {
                name => $1,
                start => $i,
                is_test => scalar(grep { is_test_attr($_) } @attrs),
                has_serial => scalar(grep { is_serial_attr($_) } @attrs),
            };
            @attrs = ();
            next;
        }

        @attrs = ();
    }

    for (my $i = 0; $i <= $#functions; $i++) {
        my $fn = $functions[$i];
        next unless $fn->{is_test};

        my $start = $fn->{start};
        my $scan_state = {
            mode => 'normal',
            block_depth => 0,
            escape => 0,
            raw_hashes => 0,
        };
        my $brace_depth = 0;
        my $seen_open_brace = 0;
        my @sanitized_lines;
        my $end = $start;

        for (my $line_index = $start; $line_index <= $#lines; $line_index++) {
            my $sanitized = strip_line_for_scan($lines[$line_index], $scan_state);
            push @sanitized_lines, $sanitized;

            my $opens = (() = $sanitized =~ /\{/g);
            my $closes = (() = $sanitized =~ /\}/g);
            $brace_depth += $opens - $closes;
            $seen_open_brace ||= $opens > 0;
            $end = $line_index;

            last if $seen_open_brace && $brace_depth <= 0;
        }

        my $body = join "\n", @sanitized_lines;
        next unless $body =~ /$hit_re/;

        $audited++;
        my $hit_line = $start + 1;
        for (my $line_index = 0; $line_index <= $#sanitized_lines; $line_index++) {
            if ($sanitized_lines[$line_index] =~ /$hit_re/) {
                $hit_line = $start + $line_index + 1;
                last;
            }
        }
        push @missing, {
            file => $file,
            line => $hit_line,
            name => $fn->{name},
        } unless $fn->{has_serial};
    }
}

if (@missing) {
    print STDERR "Missing #[serial] on tests that touch global SYNAPSE:\n";
    for my $entry (@missing) {
        my $rel = $entry->{file};
        $rel =~ s/^\Q$root\/\E//;
        print STDERR " - $rel:$entry->{line} ($entry->{name})\n";
    }
    print STDERR "Fix: add #[serial] from serial_test::serial above the affected test.\n";
    exit 1;
}

print "All singleton-touching tests carry #[serial] ($audited audited).\n";
PERL
