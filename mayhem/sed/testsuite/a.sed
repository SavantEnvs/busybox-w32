s/\(a\)\(b*\)/\2\1/g
/hello/{ s/o/0/; p; d }
1,3y/abc/xyz/
$!N;P;D
