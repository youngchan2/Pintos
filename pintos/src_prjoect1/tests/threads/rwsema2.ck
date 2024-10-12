use strict;
use warnings;
use tests::tests;
check_expected ([<<'EOF']);
(rwsema2) begin
(rwsema2) Thread main downed write.
(rwsema2) Thread main up write.
(rwsema2) Thread reader downed read.
(rwsema2) Thread reader up read.
(rwsema2) end
EOF
pass;
