package curlpro_test

import (
	"fmt"
	"log"

	"github.com/curlpro/curlpro"
)

func Example() {
	if _, err := curlpro.LoadProfiles("profiles"); err != nil {
		log.Fatal(err)
	}
	s, err := curlpro.NewSession("chrome-156-windows", curlpro.DefaultOptions())
	if err != nil {
		log.Fatal(err)
	}
	defer s.Close()

	resp, err := s.Do(&curlpro.Request{
		Method:  "GET",
		URL:     "https://tls.peet.ws/api/clean",
		Headers: map[string]string{"accept-language": "en-US,en;q=0.9"},
	})
	if err != nil {
		log.Fatal(curlpro.Code(err), err)
	}
	fmt.Println(resp.Status, resp.Proto, len(resp.Body))
}
