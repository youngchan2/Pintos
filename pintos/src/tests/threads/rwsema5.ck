use strict;
use warnings;
use tests::tests;
check_expected ([<<'EOF']);
(rwsema5) begin
(rwsema5) Thread main downed read.
(rwsema5) Thread reader downed read.
(rwsema5) Thread reader up read.
(rwsema5) Thread writer downed write.
(rwsema5) Thread writer up write.
(rwsema5) end
EOF
pass;
