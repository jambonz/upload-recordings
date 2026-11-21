// Command seed prints the SQL that creates the one table the recording
// server reads and fills it with benchmark accounts whose bucket credentials
// are encrypted exactly as the jambonz api-server encrypts them.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/jambonz/upload-recordings/go/internal/creds"
)

func main() {
	secret := flag.String("secret", "bench-secret", "ENCRYPTION_SECRET")
	key := flag.String("s3-key", "minioadmin", "S3 access key")
	skey := flag.String("s3-secret", "minioadmin", "S3 secret key")
	bucket := flag.String("bucket", "recordings", "bucket")
	mkbucket := flag.Bool("mkbucket", false, "create the bucket instead of printing SQL")
	s3URL := flag.String("s3", "https://minio:9000", "S3 endpoint for -mkbucket")
	flag.Parse()

	if *mkbucket {
		client := s3.New(s3.Options{
			Region: "us-east-1", BaseEndpoint: s3URL, UsePathStyle: true,
			Credentials: credentials.NewStaticCredentialsProvider(*key, *skey, ""),
		})
		for i := 0; ; i++ {
			_, err := client.CreateBucket(context.Background(), &s3.CreateBucketInput{Bucket: bucket})
			if err == nil || strings.Contains(err.Error(), "BucketAlreadyOwnedByYou") {
				return
			}
			if i == 30 {
				fmt.Fprintln(os.Stderr, "create bucket:", err)
				os.Exit(1)
			}
			time.Sleep(time.Second)
		}
	}

	fmt.Println(`CREATE TABLE IF NOT EXISTS accounts (
  account_sid CHAR(36) NOT NULL PRIMARY KEY,
  record_format VARCHAR(16) NOT NULL DEFAULT 'mp3',
  bucket_credential TEXT,
  eval_credential TEXT
);`)
	// account suffix -> S3 endpoint host
	endpoints := map[string]string{"": "minio:9000", "-fault": "faultproxy:9000"}
	for suffix, endpoint := range endpoints {
		cred, _ := json.Marshal(map[string]string{
			"vendor": "s3_compatible", "name": *bucket, "access_key_id": *key, "secret_access_key": *skey,
			"region": "us-east-1", "endpoint": "https://" + endpoint,
		})
		enc, err := creds.Encrypt(*secret, string(cred))
		if err != nil {
			panic(err)
		}
		for _, format := range []string{"wav", "mp3"} {
			fmt.Printf("REPLACE INTO accounts (account_sid, record_format, bucket_credential) VALUES ('acct-%s%s', '%s', '%s');\n",
				format, suffix, format, strings.ReplaceAll(enc, "'", "''"))
		}
	}
}
