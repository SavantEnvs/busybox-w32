v='a-b-c'; echo "${v//-/+}" "${v##*-}" "${v%%-*}" "${v#*-}" $(( 1 << 3 )) `echo bq`
if [ -n "$v" ] && [ "$v" != x ]; then echo yes; elif true; then echo no; fi
(echo sub; exit 3); echo $?
{ echo grp; } 2>&1 | cat
