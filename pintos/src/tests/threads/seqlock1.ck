use strict;
use warnings;
use tests::tests;
check_expected ([<<'EOF']);
(seqlock1) begin
(seqlock1) Thread main acquire write lock.
(seqlock1) Thread main release write lock.
(seqlock1) end
EOF
pass;
