# Rolling update scenario
This is actually the same as the two-dpservice scenario *except* it's a temporary state. Thus we would need to choose which scenario is doable and then run that one for a short amount of time.

## Pros
 - As it simply accepts the problems of two dpservices, it should be doable on dpservice side.
 - Once the update finishes, everything is as it was before and always was

## Cons
 - work needed in metalnet
 - metalnet would need to somehow pause updates to metalbond, copy the state to the new dpservice, then maybe resume updates to *both* (or simply stop orchestrating the old one)
 - needs proper testing
