.ok == true
and
.mutated == true
and
.reverted == true
and
(.engagement_id | length) > 0
and
.before_hash == .restored_hash
and
.after_hash != .before_hash
