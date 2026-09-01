module github.com/adithyan-ak/agenthound

go 1.25.13

// v0.5.0 through v1.0.0 are superseded unsupported publications. The historical
// v1.0.1 is also unsupported, but a numeric Git tag cannot make that canonical
// module version technically retracted. Use the explicit revision @1.0.0.
retract [v0.5.0, v1.0.0]

require (
	github.com/go-chi/chi/v5 v5.3.2
	github.com/go-chi/cors v1.2.2
	github.com/go-jose/go-jose/v4 v4.1.4
	github.com/google/jsonschema-go v0.4.3
	github.com/google/uuid v1.6.0
	github.com/gowebpki/jcs v1.0.1
	github.com/jackc/pgx/v5 v5.10.0
	github.com/modelcontextprotocol/go-sdk v1.7.0
	github.com/neo4j/neo4j-go-driver/v5 v5.28.4
	github.com/spf13/cobra v1.10.2
	github.com/spf13/pflag v1.0.10
	golang.org/x/net v0.58.0
	golang.org/x/sys v0.47.0
	golang.org/x/text v0.41.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/rogpeppe/go-internal v1.14.1 // indirect
	github.com/segmentio/asm v1.1.3 // indirect
	github.com/segmentio/encoding v0.5.4 // indirect
	github.com/yosida95/uritemplate/v3 v3.0.2 // indirect
	golang.org/x/oauth2 v0.35.0 // indirect
	golang.org/x/sync v0.22.0 // indirect
	golang.org/x/time v0.15.0 // indirect
)
