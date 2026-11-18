x=hello; y=${x#h}; z=${x%o}; echo ${x/l/L} ${#x} ${y} ${z} ${x:-def} ${u:=set}
f() { local a=$1; echo $((a * 2 + 1)); }
f 20
case $x in h*) echo match;; *) echo no;; esac
for i in 1 2 3; do echo $i; done
while read l; do :; done < /dev/null
set -- a b c; echo "$@" "$#" ${1+x}
