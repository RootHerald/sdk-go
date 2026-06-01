module github.com/rootherald/rootherald-go/examples/hello

go 1.22

require (
	github.com/go-chi/chi/v5 v5.0.12
	github.com/rootherald/rootherald-go v0.0.0
	github.com/rootherald/rootherald-go/chi v0.0.0
)

replace github.com/rootherald/rootherald-go => ../..

replace github.com/rootherald/rootherald-go/chi => ../../chi
