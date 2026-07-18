.ok == true
and
.mutated == true
and
.reverted == true
and
(.engagement_id | length) > 0
and
(.after | contains("TAMPERED-BY-AGENTHOUND-OFFLINE-HARNESS"))
and
.before == .restored
