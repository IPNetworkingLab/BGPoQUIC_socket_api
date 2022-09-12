package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"

	"crypto/tls"

	"github.com/quic-go/quic-go"
	"golang.org/x/exp/constraints"
)

// WaitGroup is used to wait for the program to finish goroutines.
var wg sync.WaitGroup

func new_channel_write(f *os.File) (func(), chan []byte) {
	c := make(chan []byte)

	return func() {
		defer wg.Done()
		for data := range c {
			f.Write(data)
		}
	}, c
}

func gen_addr(addr string, port int) string {
	ip := net.ParseIP(addr)

	/* this is a domain name !*/
	if ip == nil {
		return fmt.Sprintf("%s:%d", addr, port)
	}

	if ip.To4() != nil {
		return fmt.Sprintf("%s:%d", addr, port)
	} else {
		return fmt.Sprintf("[%s]:%d", addr, port)
	}
}

func min[T constraints.Ordered](a, b T) T {
	if a < b {
		return a
	}
	return b
}

func deepCompare(file1, file2 string) bool {
	// Check file size ...
	const chunkSize = 64000

	f1, err := os.Open(file1)
	if err != nil {
		log.Fatal(err)
	}
	defer f1.Close()

	f2, err := os.Open(file2)
	if err != nil {
		log.Fatal(err)
	}
	defer f2.Close()

	for {
		b1 := make([]byte, chunkSize)
		_, err1 := f1.Read(b1)

		b2 := make([]byte, chunkSize)
		_, err2 := f2.Read(b2)

		if err1 != nil || err2 != nil {
			if err1 == io.EOF && err2 == io.EOF {
				return true
			} else if err1 == io.EOF || err2 == io.EOF {
				return false
			} else {
				log.Fatal(err1, err2)
			}
		}

		if !bytes.Equal(b1, b2) {
			return false
		}
	}
}

func main() {
	var port *int
	var host *string
	var in_file *string
	var out_file *string
	var certificate *string
	var key *string
	var alpn *string

	port = flag.Int("p", 9876, "Contact server to this port")
	host = flag.String("host", "::1", "server addres to contact")
	alpn = flag.String("a", "echo-service", "Alpn to use")
	in_file = flag.String("i", "", "File to send to the server")
	out_file = flag.String("o", "", "File path to store what the server sends to this client. It is automatically removed when this program exits.")
	certificate = flag.String("c", "", "Provide a certificate for client authentication")
	key = flag.String("k", "", "Client private key")

	flag.Parse()

	if len(*in_file) == 0 {
		fmt.Println("in_file argument missing")
		os.Exit(1)
	}

	if len(*out_file) == 0 {
		fmt.Println("out_file argument missing")
		os.Exit(1)
	}

	if len(*certificate) == 0 {
		fmt.Println("certificate")
		os.Exit(1)
	}

	if len(*key) == 0 {
		fmt.Println("key")
		os.Exit(1)
	}

	f, err := os.OpenFile("/tmp/keys.tls", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer f.Close()

	in_stream, err := os.Open(*in_file)
	if err != nil {
		panic(err)
	}
	defer in_stream.Close()

	fin_stream, err := in_stream.Stat()
	if err != nil {
		panic(err)
	}
	in_file_size := fin_stream.Size()

	cert_pem, err := os.ReadFile(*certificate)

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	key_pem, err := os.ReadFile(*key)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	out_stream, err := os.Create(*out_file)
	defer os.Remove(*out_file)


	tlsCert, err := tls.X509KeyPair(cert_pem, key_pem)
	if err != nil {
		panic(err)
	}

	full_addr := gen_addr(*host, *port)

	tls_conf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{*alpn},
		Certificates:       []tls.Certificate{tlsCert},
	}

	conn, err := quic.DialAddr(full_addr, tls_conf, nil)
	if err != nil {
		panic(err)
	}

	strm, err := conn.OpenStreamSync(context.Background())

	gen_write, cha := new_channel_write(out_stream)

	wg.Add(2)
	go gen_write()

	go func () {
	    var curr_read int64 = 0

        for curr_read < in_file_size {
            a := make([]byte, 4096)
            act, err := io.ReadAtLeast(strm, a, int(min(4096, in_file_size-curr_read)))
            if err != nil {
                panic(err)
            }

            curr_read += int64(act)
            cha <- a
        }
        close(cha)
        wg.Done()
	}()



	if _, err := io.CopyN(strm, in_stream, in_file_size); err != nil {
	    panic(err)
	}

	wg.Wait()

	out_stream.Close()
	strm.Close()
	conn.CloseWithError(0, "")

	if !deepCompare(*out_file, *in_file) {
	    fmt.Println("Files does not match!")
		os.Exit(1)
	}
}
