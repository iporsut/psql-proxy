package main

import (
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"

	"github.com/jeroenrinzema/psql-wire/pkg/buffer"
)

var listening = flag.String("l", ":5434", "port the proxy is listening on")
var dial = flag.String("d", "127.0.0.1:5433", "PostgreSQL server target")
var tls = flag.Bool("tls", false, "this flag has to be set whenever the server is supporting TLS connections")

func main() {
	flag.Parse()

	slog.SetLogLoggerLevel(slog.LevelError)

	err := run()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func run() error {
	listener, err := net.Listen("tcp", *listening)
	if err != nil {
		return err
	}

	slog.Info("proxy listening", slog.String("address", *listening))

	for {
		client, err := listener.Accept()
		if err != nil {
			return err
		}

		slog.Info("incoming connection, dialing PostgreSQL server!")

		db, err := net.Dial("tcp", *dial)
		if err != nil {
			return err
		}

		go sniffer(client, db)
	}
}

func sniffer(client, db net.Conn) {
	to := io.TeeReader(client, db)
	from := io.TeeReader(db, client)

	slog.Info("starting sniffing the PSQL packages")

	var done bool

	go func() {
		defer func() {
			done = true
		}()
		defer db.Close()
		reader := buffer.NewReader(slog.Default(), to, 1406920893)
		_, err := reader.ReadUntypedMsg()
		if err != nil {
			slog.Info("unexpected error while reading the client version", slog.String("err", err.Error()))
			return
		}

		version, _ := reader.GetUint32()
		slog.Info("-->", slog.Uint64("version", uint64(version)))

		if !*tls {
			// NOTE: we have to read a untyped message twice if TLS is disabled (check handshake)
			reader.ReadUntypedMsg()
		}

		for !done {
			t, _, err := reader.ReadTypedMsg()
			if err == io.EOF {
				return
			}

			if err != nil {
				slog.Info("unexpected error while reading a typed client message", slog.String("err", err.Error()))
				continue
			}

			slog.Info("->>", slog.String("type", string(t)), slog.String("msg", string(reader.Msg)))
		}
	}()

	go func() {
		defer func() {
			done = true
		}()
		defer client.Close()
		if !*tls {
			bb := make([]byte, 1)
			_, err := from.Read(bb)
			if err != nil {
				slog.Info("unexpected error while reading the tls response", slog.String("err", err.Error()))
				return
			}
		}

		reader := buffer.NewReader(slog.Default(), from, 1406920893)
		for !done {
			t, _, err := reader.ReadTypedMsg()
			if err == io.EOF {
				return
			}

			if err != nil {
				slog.Info("unexpected error while reading the server response", slog.String("err", err.Error()))
				continue
			}

			slog.Info("<<-", slog.String("type", string(t)), slog.String("msg", string(reader.Msg)))
		}
	}()
}
