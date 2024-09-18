use strict;
use warnings;
use tests::tests;
check_expected ([<<'EOF']);
(seqlock5) begin
(seqlock5) end
EOF
pass;
