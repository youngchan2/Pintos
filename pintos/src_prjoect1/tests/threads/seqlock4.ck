use strict;
use warnings;
use tests::tests;
check_expected ([<<'EOF']);
(seqlock4) begin
(seqlock4) end
EOF
pass;
