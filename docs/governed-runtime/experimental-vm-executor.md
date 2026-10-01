# Experimental VM guest executor

The Stage 0 host-simulated guest seam, Stage 1A one-shot VM executor, Stage 1B persistent device custody and Stage 1D session proxy are experimental reusable product source. They are not promoted or a supported deployment commitment.

The source modules and guest source/build tools retain bounded framed requests, exact work binding and executor-local custody. Docket authorization propagation remains in the current governed executor path. Build images explicitly with the stage-specific image builders; no prebuilt images or device state are distributed.

Run the library tests and `cargo test -p gwr-local --test stage0_guest_process` for deterministic local checks. Real VM execution, provider calls, measurements and qualification runs require separate authorization. Historical qualification matrices and captured occurrences remain outside this development line.

The Stage 0 seam accepts the inner V1 request directly for deterministic local testing. It is not enrolled for the current signed V2 governed dispatch; that path refuses before a guest effect. The VM/session prototypes share this experimental transport boundary and do not establish current executor enrollment.
