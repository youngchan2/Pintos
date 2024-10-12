use strict;
use warnings;
use tests::tests;
check_expected ([<<'EOF']);
(rwsema6) begin
(rwsema6) Thread main downed write.
(rwsema6) Thread main up write.
(rwsema6) Thread writer downed write.
(rwsema6) Thread writer up write.
(rwsema6) Thread reader downed read.
(rwsema6) Thread reader up read.
(rwsema6) end
EOF
pass;
