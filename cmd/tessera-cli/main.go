package main

func main() {
	if err := newRoot().Execute(); err != nil {
		panic(err)
	}
}
