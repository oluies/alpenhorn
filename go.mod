module vuvuzela.io/alpenhorn

go 1.25.0

// The vuvuzela.io vanity import domain is currently unreachable.
// Map the sister modules to their canonical GitHub repositories so
// builds work without depending on the vanity redirector.
replace (
	vuvuzela.io/concurrency => github.com/vuvuzela/concurrency v0.0.0-20190327123758-e608f351e310
	vuvuzela.io/crypto => github.com/vuvuzela/crypto v0.0.0-20220523120157-1709ed3a3b66
	vuvuzela.io/internal => github.com/vuvuzela/internal v0.0.0-20190910144301-7321cf92c8ba
	vuvuzela.io/vuvuzela => github.com/vuvuzela/vuvuzela v0.0.0-20190912153956-55ba49f81ad0
)

require (
	github.com/boltdb/bolt v1.3.1
	github.com/davidlazar/easyjson v0.0.0-20170924022152-f8e31516abf8
	github.com/davidlazar/go-crypto v0.0.0-20200604182044-b73af7476f6c
	github.com/davidlazar/mapstructure v0.0.0-20170906201703-c9d7ddc4ff97
	github.com/dchest/siphash v1.2.3
	github.com/dgraph-io/badger v1.6.2
	github.com/gorilla/websocket v1.5.3
	github.com/mattn/go-isatty v0.0.22
	github.com/sirupsen/logrus v1.9.4
	golang.org/x/crypto v0.52.0
	golang.org/x/net v0.55.0
	google.golang.org/grpc v1.81.1
	vuvuzela.io/concurrency v0.0.0-00010101000000-000000000000
	vuvuzela.io/crypto v0.0.0-00010101000000-000000000000
	vuvuzela.io/internal v0.0.0-00010101000000-000000000000
	vuvuzela.io/vuvuzela v0.0.0-00010101000000-000000000000
)

require (
	github.com/AndreasBriese/bbloom v0.0.0-20190825152654-46b345b51c96 // indirect
	github.com/cespare/xxhash v1.1.0 // indirect
	github.com/dgraph-io/ristretto v0.0.2 // indirect
	github.com/dustin/go-humanize v1.0.0 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/kylelemons/godebug v1.1.0 // indirect
	github.com/pkg/errors v0.8.1 // indirect
	golang.org/x/sys v0.45.0 // indirect
	golang.org/x/term v0.43.0 // indirect
	golang.org/x/text v0.37.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260226221140-a57be14db171 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)
