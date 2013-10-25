AFCD
====

AFCD: An Approximated-Fair and Controlled-Delay Queuing for High Speed Networks

An implementation in Linux kernel for AFCD.

High speed networks have characteristics of high
bandwidth, long queuing delay, and high burstiness which make
it difficult to address issues such as fairness, low queuing delay
and high link utilization. Current high speed networks carry
heterogeneous TCP flows which makes it even more challenging
to address these issues. Since sender centric approaches do
not meet these challenges, there have been several proposals
to address them at router level via queue management (QM)
schemes. These QM schemes have been fairly successful in
addressing either fairness issues or large queuing delay but not
both at the same time. We propose a new QM scheme called
Approximated-Fair and Controlled-Delay (AFCD) queuing for
high speed networks that aims to meet following design goals:
approximated fairness, controlled low queuing delay, high link
utilization and simple implementation. The design of AFCD
utilizes a novel synergistic approach by forming an alliance
between approximated fair queuing and controlled delay queuing.
It uses very small amount of state information in sending rate
estimation of flows and makes drop decision based on a target
delay of individual flow. Through experimental evaluation in a
10Gbps high speed networking environment, we show AFCD
meets our design goals by maintaining approximated fair share
of bandwidth among flows and ensuring a controlled very low
queuing delay with a comparable link utilization.

Lin Xue
xuelinsmann@gmail.com
