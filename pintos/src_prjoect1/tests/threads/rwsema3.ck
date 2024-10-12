use strict;
use warnings;
use tests::tests;
check_expected ([<<'EOF']);
(rwsema3) begin
(rwsema3) Thread main downed read.
(rwsema3) Thread main up read.
(rwsema3) Thread writer downed write.
(rwsema3) Thread writer up write.
(rwsema3) end
EOF
pass;
