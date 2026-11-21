package creds

import "testing"

func TestRoundTrip(t *testing.T) {
	const plain = `{"vendor":"aws_s3","name":"b","access_key_id":"AK","secret_access_key":"SK","region":"eu-west-1"}`
	enc, err := Encrypt("s3cret", plain)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decrypt("s3cret", enc)
	if err != nil || got != plain {
		t.Fatalf("got %q, %v", got, err)
	}
	if _, err := Decrypt("wrong", enc); err == nil {
		t.Fatal("decrypting with the wrong secret succeeded")
	}
}

// A credential encrypted by the jambonz api-server's own code
// (lib/utils/encrypt-decrypt.js, aes-256-cbc) with ENCRYPTION_SECRET "foobar".
func TestDecryptAPIServerVector(t *testing.T) {
	const enc = `{"iv":"000102030405060708090a0b0c0d0e0f","content":"5d8f319fe057f07c7d1f543b66ad71eda5db7a3792defff0af332ab2866c38ba259dccc29cf06b933975d6d76263a7c0"}`
	got, err := Decrypt("foobar", enc)
	if err != nil || got != `{"vendor":"aws_s3","name":"my-bucket"}` {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestParseBucket(t *testing.T) {
	cases := []struct {
		in     string
		region string
	}{
		{`{"vendor":"s3_compatible","name":"b","endpoint":"https://s3.eu-central-2.wasabisys.com"}`, "eu-central-2"},
		{`{"vendor":"s3_compatible","name":"b","endpoint":"s3.us-west-1.example.com"}`, "us-west-1"},
		{`{"vendor":"s3_compatible","name":"b","endpoint":"https://minio.example.com","region":"x"}`, "x"},
		{`{"vendor":"s3_compatible","name":"b","endpoint":"https://minio.example.com"}`, ""},
		{`{"vendor":"aws_s3","name":"b","region":"us-east-2"}`, "us-east-2"},
	}
	for _, c := range cases {
		b, err := ParseBucket(c.in)
		if err != nil || b.Region != c.region || b.Name != "b" {
			t.Errorf("%s: got %+v, %v", c.in, b, err)
		}
	}
	g, _ := ParseBucket(`{"vendor":"google","name":"gb","service_key":"{\"private_key\":\"PK\",\"client_email\":\"a@b\",\"token_uri\":\"https://t\"}"}`)
	if g.PrivateKey != "PK" || g.ClientEmail != "a@b" || g.TokenURI != "https://t" {
		t.Errorf("google: %+v", g)
	}
	a, _ := ParseBucket(`{"vendor":"azure","name":"c","connection_string":"CS"}`)
	if a.ConnectionString != "CS" || a.Name != "c" {
		t.Errorf("azure: %+v", a)
	}
}
