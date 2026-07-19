.ok == true
and
.mutated == true
and
.reverted == true
and
.semantic_reverted == true
and
(.engagement_id | length) > 0
and
.server_name == "agenthound-implant-fixture"
and
.after_hash != .before_hash
