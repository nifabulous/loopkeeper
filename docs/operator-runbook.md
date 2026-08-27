# Operator runbook

1. Keep the read-only caller enabled first. Confirm artifacts contain a review
   or triage result and that no comment or issue write occurred.
2. Verify `LOOPKEEPER_TRUSTED_SHA`, the forge-resolved default-branch tip, and
   the immutable Loopkeeper release SHA are distinct, valid full commits.
3. For a disposable consumer only, enable the posting caller. It must set
   `post_comments: true`; the adapter itself still requires
   `LOOPKEEPER_OPERATOR=1` in every write function.
4. Exercise fallback evidence, later CI replacement, duplicate reconciliation,
   and a replay at the same head. Expect one current-head canonical comment.
5. If comment history, workflow identity, check runs, or the gap label cannot
   be read within bounds, preserve the fallback artifact and investigate. Never
   treat unavailable evidence as “no CI run.”
6. Keep `--gap-issues` disabled until the real-PR gate has passed and the label
   has been independently verified. A missing label must yield
   `GAP_LABEL_UNAVAILABLE` with no write.

For key rotation, publish the new protected `key_id`, verify the overlap window,
remove the retired key, and rerun the attestation matrix. For an incident,
disable posting callers, preserve artifacts and workflow summaries, rotate the
model/attestation credentials if exposure is suspected, and record the exact
release SHA in the incident note.
