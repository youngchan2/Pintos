use strict;
use warnings;
use tests::tests;
check_expected ([<<'EOF']);
(rwsema4) begin
(rwsema4) Thread main downed read.
(rwsema4) Thread reader downed read.
(rwsema4) Thread reader up read.
(rwsema4) Thread main up read.
(rwsema4) end
EOF
pass;
