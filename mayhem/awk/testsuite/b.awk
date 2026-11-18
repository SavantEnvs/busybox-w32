{ sum += $1; w[NR % 3] = $0 } END { print sum, NR; for (k in w) print k, w[k]; while (i++ < 3) { if (i == 2) continue; print i } do { j++ } while (j < 3); print j }
