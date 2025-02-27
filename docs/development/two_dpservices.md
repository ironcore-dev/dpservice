# Constant two-dpservice scenario
The idea is to have two separate instances of dpservice running. But what to do about packets?

## Both dpservices get the same packets (complete duplication)
This way all traffic is seen by both processes and they need to decide what to do.

### Pros
 - simple architecture (code complexity unclear, may be possible)
 - underlay traffic is easy, as dpservice will simply drop packets that are not regirested for it

### Cons
 - performance considerations
 - VM traffic will get duplicated, there is no way to tell which is the "right" dpservice

### Analysis
 - may be doable
 - need to somehow share memory to tell which VM pentuple should be passed by which instance
 - however what happens when the "right" instance gets down?

## Each dpservice gets the "right" traffic

### Pros
 - underlay is doable via RTE rules for each underlay address (i.e. wrhong underlay addresses will not reach dpservice)

### Cons
 - not sure if doable as packet duplication is somewhere in DPDK
 - overlay traffic - to tell which traffic is "right" for which dpservice is non-solvable without information in dpservice itself

### Analysis
 - cannot be done due to the above

## Only one (random) dpservice gets each packet

### Pros
 - performace should be nice, no duplicate work
 - should be doable if both instances share memory

### Cons 
 - DPDK does not share memory across instances, this would absolutely non-systematic and manual solution
 - Not sure if we can force DPDK/MEllanox to not duplicate packets
 - We would also need to share ALL connection tracking tables, possibly other stuff, like TCP state machine, etc.

### Analysis
 - possibly not even doable
 - if doable, the cost seems to high, reworking the whole connection tracking architecture
