// Package collector defines the legacy enumerator contract used by the v0
// modules under modules/. Modules in modules/ satisfy this interface;
// sdk/action.Enumerator is the forward-going contract for v1+. Both contracts
// coexist during the v0 migration — the legacy Collector contract is what the
// three shipped modules implement today, and sdk/action.Enumerator is the
// future-vision contract that nothing implements yet. They will reconverge
// at v1 once the migration is complete.
package collector
