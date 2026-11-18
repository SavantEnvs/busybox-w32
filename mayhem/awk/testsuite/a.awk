BEGIN { x = "a b c"; n = split(x, arr, " "); for (i = 1; i <= n; i++) s = s arr[i]; print s, length(s), substr(x, 2, 3), toupper(x); printf "%d %s %5.2f\n", 42, "str", 3.14159
  if (match(x, /b+/)) print RSTART, RLENGTH; gsub(/a/, "[&]", x); print x; y["k"] = 1; delete y["k"]; print 1+2*3, index("hello","ll"), sprintf("%c", 65) }
function f(a, b) { return a b }
END { print f(1, 2) }
