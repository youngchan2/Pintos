use strict;
use warnings;
use tests::tests;
check_expected ([<<'EOF']);
(seqlock3) begin
(seqlock3) writer acquire seqlock!.
(seqlock3) writer release seqlock!.
(seqlock3) end
EOF
pass;
