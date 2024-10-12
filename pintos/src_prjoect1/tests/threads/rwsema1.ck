use strict;
use warnings;
use tests::tests;
check_expected ([<<'EOF']);
(rwsema1) begin
(rwsema1) Thread main downed write.
(rwsema1) Thread main up write.
(rwsema1) Thread writer downed write.
(rwsema1) Thread writer up write.
(rwsema1) end
EOF
pass;
