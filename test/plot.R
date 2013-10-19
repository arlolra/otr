#!/usr/bin/env Rscript

# most from ry
# https://github.com/joyent/node/blob/master/benchmark/plot.R

library(ggplot2)

hist_png_filename <- "hist.png"

png(filename = hist_png_filename, width = 480, height = 380, units = "px")

da = read.csv(
  "./data.csv",
  sep="\t",
  header=F,
  col.names = c("time")
)

p <- qplot(
  time,
  data=da,
  geom="histogram",
  #binwidth=10,
  main="xxx",
  xlab="key generation time (ms)"
)

p + scale_x_continuous(limits = c(0000, 15000))

print(hist_png_filename)
