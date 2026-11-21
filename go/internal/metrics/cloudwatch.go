package metrics

import (
	"context"
	"io"
	"log/slog"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
)

// RunCloudWatch publishes RecordingSessionCount to the Jambonz/Recording
// namespace every 30 seconds until ctx is cancelled. It is a no-op unless the
// process runs on EC2 with credentials that may call PutMetricData.
//
// It is meant to be run in its own goroutine: probing the instance metadata
// service takes seconds when there is none, and the C++ service blocked
// startup on it.
func RunCloudWatch(ctx context.Context, log *slog.Logger, sessions func() int64) {
	probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	md := imds.New(imds.Options{})
	get := func(path string) string {
		out, err := md.GetMetadata(probeCtx, &imds.GetMetadataInput{Path: path})
		if err != nil {
			return ""
		}
		defer out.Content.Close()
		b, _ := io.ReadAll(out.Content)
		return string(b)
	}
	instanceID := get("instance-id")
	if instanceID == "" {
		log.Info("Not running on EC2, CloudWatch metrics disabled")
		return
	}
	instanceType := get("instance-type")
	az := get("placement/availability-zone")
	log.Info("Detected EC2 instance", "instance_id", instanceID, "instance_type", instanceType)

	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(get("placement/region")))
	if err != nil {
		log.Warn("No AWS credentials found, CloudWatch metrics disabled", "err", err)
		return
	}
	cw := cloudwatch.NewFromConfig(cfg)

	// Same permission probe the C++ service makes.
	_, err = cw.PutMetricData(ctx, &cloudwatch.PutMetricDataInput{
		Namespace: aws.String("JambonzTest"),
		MetricData: []types.MetricDatum{{
			MetricName: aws.String("PermissionTest"),
			Value:      aws.Float64(0),
			Timestamp:  aws.Time(time.Now()),
		}},
	})
	if err != nil {
		log.Warn("CloudWatch permission test failed, metrics disabled", "err", err)
		return
	}
	log.Info("CloudWatch permissions verified, publishing session count every 30s")

	dims := []types.Dimension{{Name: aws.String("InstanceId"), Value: aws.String(instanceID)}}
	if instanceType != "" {
		dims = append(dims, types.Dimension{Name: aws.String("InstanceType"), Value: aws.String(instanceType)})
	}
	if az != "" {
		dims = append(dims, types.Dimension{Name: aws.String("AvailabilityZone"), Value: aws.String(az)})
	}

	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()
	for {
		_, err := cw.PutMetricData(ctx, &cloudwatch.PutMetricDataInput{
			Namespace: aws.String("Jambonz/Recording"),
			MetricData: []types.MetricDatum{{
				MetricName: aws.String("RecordingSessionCount"),
				Value:      aws.Float64(float64(sessions())),
				Timestamp:  aws.Time(time.Now()),
				Dimensions: dims,
			}},
		})
		if err != nil && ctx.Err() == nil {
			log.Error("Failed to publish CloudWatch metric", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}
