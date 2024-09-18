use strict;
use warnings;
use tests::tests;
check_expected ([<<'EOF']);
(seqlock2) begin
(seqlock2) Thread main acquire write lock.
(seqlock2) Thread main release write lock.
(seqlock2) end
EOF
pass;
