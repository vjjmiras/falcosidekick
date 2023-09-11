package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/DataDog/datadog-go/statsd"
	"github.com/embano1/memlog"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/falcosecurity/falcosidekick/outputs"
	"github.com/falcosecurity/falcosidekick/types"
)

// Globale variables
var (
	nullClient *outputs.Client
	/**
	slackClient         *outputs.Client
	cliqClient          *outputs.Client
	rocketchatClient    *outputs.Client
	mattermostClient    *outputs.Client
	teamsClient         *outputs.Client
	datadogClient       *outputs.Client
	discordClient       *outputs.Client
	alertmanagerClient  *outputs.Client
	elasticsearchClient *outputs.Client
	influxdbClient      *outputs.Client
	lokiClient          *outputs.Client
	natsClient          *outputs.Client
	stanClient          *outputs.Client
	awsClient           *outputs.Client
	smtpClient          *outputs.Client
	opsgenieClient      *outputs.Client
	webhookClient       *outputs.Client
	noderedClient       *outputs.Client
	cloudeventsClient   *outputs.Client
	azureClient         *outputs.Client
	gcpClient           *outputs.Client
	googleChatClient    *outputs.Client
	kafkaClient         *outputs.Client
	kafkaRestClient     *outputs.Client
	pagerdutyClient     *outputs.Client
	gcpCloudRunClient   *outputs.Client
	kubelessClient      *outputs.Client
	openfaasClient      *outputs.Client
	tektonClient        *outputs.Client
	webUIClient         *outputs.Client
	policyReportClient  *outputs.Client
	rabbitmqClient      *outputs.Client
	wavefrontClient     *outputs.Client
	fissionClient       *outputs.Client
	grafanaClient       *outputs.Client
	grafanaOnCallClient *outputs.Client
	yandexClient        *outputs.Client
	syslogClient        *outputs.Client
	mqttClient          *outputs.Client
	zincsearchClient    *outputs.Client
	gotifyClient        *outputs.Client
	spyderbatClient     *outputs.Client
	timescaleDBClient   *outputs.Client
	redisClient         *outputs.Client
	telegramClient      *outputs.Client
	n8nClient           *outputs.Client
	openObserveClient   *outputs.Client
	dynatraceClient     *outputs.Client
	**/

	statsdClient, dogstatsdClient *statsd.Client
	config                        *types.Configuration
	stats                         *types.Statistics
	promStats                     *types.PromStatistics

	regPromLabels *regexp.Regexp
)

func init() {
	// detect unit testing and skip init.
	// see: https://github.com/alecthomas/kingpin/issues/187
	testing := (strings.HasSuffix(os.Args[0], ".test") ||
		strings.HasSuffix(os.Args[0], "__debug_bin"))
	if testing {
		return
	}

	regPromLabels, _ = regexp.Compile("^[a-zA-Z_:][a-zA-Z0-9_:]*$")

	config = getConfig()
	stats = getInitStats()
	promStats = getInitPromStats(config)

	outputs.EnabledClients = make(map[string]*outputs.Client)

	nullClient = &outputs.Client{
		OutputType:      "null",
		Config:          config,
		Stats:           stats,
		PromStats:       promStats,
		StatsdClient:    statsdClient,
		DogstatsdClient: dogstatsdClient,
	}

	outputs.EnabledClients["nullClient"] = nullClient

	if config.Statsd.Forwarder != "" {
		client, err := outputs.NewStatsdClient("StatsD", config, stats)
		if err != nil {
			config.Statsd.Forwarder = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "StatsD")
			outputs.EnabledClients["nullClient"].StatsdClient = client
			nullClient.DogstatsdClient = client
		}
	}

	if config.Dogstatsd.Forwarder != "" {
		client, err := outputs.NewStatsdClient("DogStatsD", config, stats)
		if err != nil {
			config.Statsd.Forwarder = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "DogStatsD")
			outputs.EnabledClients["nullClient"].DogstatsdClient = client
			nullClient.DogstatsdClient = client
		}
	}

	if config.Slack.WebhookURL != "" {
		client, err := outputs.NewClient("Slack", config.Slack.WebhookURL, config.Slack.MutualTLS, config.Slack.CheckCert, config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.Slack.WebhookURL = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "Slack")
			outputs.EnabledClients["Slack"] = client
		}
	}

	if config.Cliq.WebhookURL != "" {
		client, err := outputs.NewClient("Cliq", config.Cliq.WebhookURL, config.Cliq.MutualTLS, config.Cliq.CheckCert, config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.Cliq.WebhookURL = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "Cliq")
			outputs.EnabledClients["Cliq"] = client
		}
	}

	if config.Rocketchat.WebhookURL != "" {
		client, err := outputs.NewClient("Rocketchat", config.Rocketchat.WebhookURL, config.Rocketchat.MutualTLS, config.Rocketchat.CheckCert, config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.Rocketchat.WebhookURL = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "Rocketchat")
			outputs.EnabledClients["Rocketchat"] = client
		}
	}

	if config.Mattermost.WebhookURL != "" {
		client, err := outputs.NewClient("Mattermost", config.Mattermost.WebhookURL, config.Mattermost.MutualTLS, config.Mattermost.CheckCert, config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.Mattermost.WebhookURL = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "Mattermost")
			outputs.EnabledClients["Mattermost"] = client
		}
	}

	if config.Teams.WebhookURL != "" {
		client, err := outputs.NewClient("Teams", config.Teams.WebhookURL, config.Teams.MutualTLS, config.Teams.CheckCert, config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.Teams.WebhookURL = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "Teams")
			outputs.EnabledClients["Teams"] = client
		}
	}

	if config.Datadog.APIKey != "" {
		client, err := outputs.NewClient("Datadog", config.Datadog.Host+outputs.DatadogPath+"?api_key="+config.Datadog.APIKey, config.Datadog.MutualTLS, config.Datadog.CheckCert, config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.Datadog.APIKey = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "Datadog")
			outputs.EnabledClients["Datadog"] = client
		}
	}

	if config.Discord.WebhookURL != "" {
		client, err := outputs.NewClient("Discord", config.Discord.WebhookURL, config.Discord.MutualTLS, config.Discord.CheckCert, config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.Discord.WebhookURL = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "Discord")
			outputs.EnabledClients["Discord"] = client
		}
	}

	if config.Alertmanager.HostPort != "" {
		client, err := outputs.NewClient("AlertManager", config.Alertmanager.HostPort+config.Alertmanager.Endpoint, config.Alertmanager.MutualTLS, config.Alertmanager.CheckCert, config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.Alertmanager.HostPort = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "AlertManager")
			outputs.EnabledClients["AlertManager"] = client
		}
	}

	if config.Elasticsearch.HostPort != "" {
		client, err := outputs.NewClient("Elasticsearch", config.Elasticsearch.HostPort+"/"+config.Elasticsearch.Index+"/"+config.Elasticsearch.Type, config.Elasticsearch.MutualTLS, config.Elasticsearch.CheckCert, config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.Elasticsearch.HostPort = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "Elasticsearch")
			outputs.EnabledClients["Elasticsearch"] = client
		}
	}

	if config.Loki.HostPort != "" {
		client, err := outputs.NewClient("Loki", config.Loki.HostPort+config.Loki.Endpoint, config.Loki.MutualTLS, config.Loki.CheckCert, config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.Loki.HostPort = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "Loki")
			outputs.EnabledClients["Loki"] = client
		}
	}

	if config.Nats.HostPort != "" {
		client, err := outputs.NewClient("NATS", config.Nats.HostPort, config.Nats.MutualTLS, config.Nats.CheckCert, config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.Nats.HostPort = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "NATS")
			outputs.EnabledClients["NATS"] = client
		}
	}

	if config.Stan.HostPort != "" && config.Stan.ClusterID != "" && config.Stan.ClientID != "" {
		client, err := outputs.NewClient("STAN", config.Stan.HostPort, config.Stan.MutualTLS, config.Stan.CheckCert, config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.Stan.HostPort = ""
			config.Stan.ClusterID = ""
			config.Stan.ClientID = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "STAN")
			outputs.EnabledClients["STAN"] = client
		}
	}

	if config.Influxdb.HostPort != "" {
		var url = config.Influxdb.HostPort
		if config.Influxdb.Organization != "" && config.Influxdb.Bucket != "" {
			url += "/api/v2/write?org=" + config.Influxdb.Organization + "&bucket=" + config.Influxdb.Bucket
		} else if config.Influxdb.Database != "" {
			url += "/write?db=" + config.Influxdb.Database
		}
		if config.Influxdb.User != "" && config.Influxdb.Password != "" && config.Influxdb.Token == "" {
			url += "&u=" + config.Influxdb.User + "&p=" + config.Influxdb.Password
		}
		if config.Influxdb.Precision != "" {
			url += "&precision=" + config.Influxdb.Precision
		}

		client, err := outputs.NewClient("Influxdb", url, config.Influxdb.MutualTLS, config.Influxdb.CheckCert, config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.Influxdb.HostPort = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "Influxdb")
			outputs.EnabledClients["Influxdb"] = client
		}
	}

	if config.AWS.Lambda.FunctionName != "" || config.AWS.SQS.URL != "" ||
		config.AWS.SNS.TopicArn != "" || config.AWS.CloudWatchLogs.LogGroup != "" || config.AWS.S3.Bucket != "" ||
		config.AWS.Kinesis.StreamName != "" || (config.AWS.SecurityLake.Bucket != "" && config.AWS.SecurityLake.Region != "" && config.AWS.SecurityLake.AccountID != "") {

		client, err := outputs.NewAWSClient(config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.AWS.AccessKeyID = ""
			config.AWS.SecretAccessKey = ""
			config.AWS.Region = ""
			config.AWS.Lambda.FunctionName = ""
			config.AWS.SQS.URL = ""
			config.AWS.S3.Bucket = ""
			config.AWS.SNS.TopicArn = ""
			config.AWS.CloudWatchLogs.LogGroup = ""
			config.AWS.CloudWatchLogs.LogStream = ""
			config.AWS.Kinesis.StreamName = ""
			config.AWS.SecurityLake.Region = ""
			config.AWS.SecurityLake.Bucket = ""
			config.AWS.SecurityLake.AccountID = ""
		} else {
			if config.AWS.Lambda.FunctionName != "" {
				outputs.EnabledOutputs = append(outputs.EnabledOutputs, "AWSLambda")
				outputs.EnabledClients["AWSLambda"] = client
			}
			if config.AWS.SQS.URL != "" {
				outputs.EnabledOutputs = append(outputs.EnabledOutputs, "AWSSQS")
				outputs.EnabledClients["AWSSQS"] = client
			}
			if config.AWS.SNS.TopicArn != "" {
				outputs.EnabledOutputs = append(outputs.EnabledOutputs, "AWSSNS")
				outputs.EnabledClients["AWSSNS"] = client
			}
			if config.AWS.CloudWatchLogs.LogGroup != "" {
				outputs.EnabledOutputs = append(outputs.EnabledOutputs, "AWSCloudWatchLogs")
				outputs.EnabledClients["AWSCloudWatchLogs"] = client
			}
			if config.AWS.S3.Bucket != "" {
				outputs.EnabledOutputs = append(outputs.EnabledOutputs, "AWSS3")
				outputs.EnabledClients["AWSS3"] = client

			}
			if config.AWS.Kinesis.StreamName != "" {
				outputs.EnabledOutputs = append(outputs.EnabledOutputs, "AWSKinesis")
				outputs.EnabledClients["AWSKinesis"] = client
			}
			if config.AWS.SecurityLake.Bucket != "" && config.AWS.SecurityLake.Region != "" && config.AWS.SecurityLake.AccountID != "" && config.AWS.SecurityLake.Prefix != "" {
				config.AWS.SecurityLake.Ctx = context.Background()
				config.AWS.SecurityLake.ReadOffset, config.AWS.SecurityLake.WriteOffset = new(memlog.Offset), new(memlog.Offset)
				config.AWS.SecurityLake.Memlog, err = memlog.New(config.AWS.SecurityLake.Ctx, memlog.WithMaxSegmentSize(10000))
				if config.AWS.SecurityLake.Interval < 5 {
					config.AWS.SecurityLake.Interval = 5
				}
				go client.StartSecurityLakeWorker()
				if err != nil {
					config.AWS.SecurityLake.Region = ""
					config.AWS.SecurityLake.Bucket = ""
					config.AWS.SecurityLake.AccountID = ""
					config.AWS.SecurityLake.Prefix = ""
				} else {
					outputs.EnabledOutputs = append(outputs.EnabledOutputs, "AWSSecurityLake")
					outputs.EnabledClients["AWSSecurityLake"] = client
				}
			}
		}
	}

	if config.SMTP.HostPort != "" && config.SMTP.From != "" && config.SMTP.To != "" {
		client, err := outputs.NewSMTPClient(config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.SMTP.HostPort = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "SMTP")
			outputs.EnabledClients["SMTP"] = client
		}
	}

	if config.Opsgenie.APIKey != "" {
		url := "https://api.opsgenie.com/v2/alerts"
		if strings.ToLower(config.Opsgenie.Region) == "eu" {
			url = "https://api.eu.opsgenie.com/v2/alerts"
		}
		client, err := outputs.NewClient("Opsgenie", url, config.Opsgenie.MutualTLS, config.Opsgenie.CheckCert, config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.Opsgenie.APIKey = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "Opsgenie")
			outputs.EnabledClients["Opsgenie"] = client
		}
	}

	if config.Webhook.Address != "" {
		client, err := outputs.NewClient("Webhook", config.Webhook.Address, config.Webhook.MutualTLS, config.Webhook.CheckCert, config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.Webhook.Address = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "Webhook")
			outputs.EnabledClients["Webhook"] = client
		}
	}

	if config.NodeRed.Address != "" {
		client, err := outputs.NewClient("NodeRed", config.NodeRed.Address, false, config.NodeRed.CheckCert, config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.NodeRed.Address = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "NodeRed")
			outputs.EnabledClients["NodeRed"] = client
		}
	}

	if config.CloudEvents.Address != "" {
		client, err := outputs.NewClient("CloudEvents", config.CloudEvents.Address, config.CloudEvents.MutualTLS, config.CloudEvents.CheckCert, config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.CloudEvents.Address = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "CloudEvents")
			outputs.EnabledClients["CloudEvents"] = client
		}
	}

	if config.Azure.EventHub.Name != "" {
		client, err := outputs.NewEventHubClient(config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.Azure.EventHub.Name = ""
			config.Azure.EventHub.Namespace = ""
		} else {
			if config.Azure.EventHub.Name != "" {
				outputs.EnabledOutputs = append(outputs.EnabledOutputs, "EventHub")
				outputs.EnabledClients["EventHub"] = client
			}
		}
	}

	if (config.GCP.PubSub.ProjectID != "" && config.GCP.PubSub.Topic != "") || config.GCP.Storage.Bucket != "" || config.GCP.CloudFunctions.Name != "" {
		client, err := outputs.NewGCPClient(config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.GCP.PubSub.ProjectID = ""
			config.GCP.PubSub.Topic = ""
			config.GCP.Storage.Bucket = ""
			config.GCP.CloudFunctions.Name = ""
		} else {
			if config.GCP.PubSub.Topic != "" && config.GCP.PubSub.ProjectID != "" {
				outputs.EnabledOutputs = append(outputs.EnabledOutputs, "GCPPubSub")
				outputs.EnabledClients["GCPPubSub"] = client
			}
			if config.GCP.Storage.Bucket != "" {
				outputs.EnabledOutputs = append(outputs.EnabledOutputs, "GCPStorage")
				outputs.EnabledClients["GCPStorage"] = client
			}
			if config.GCP.CloudFunctions.Name != "" {
				outputs.EnabledOutputs = append(outputs.EnabledOutputs, "GCPCloudFunctions")
				outputs.EnabledClients["GCPCloudFunctions"] = client
			}
		}
	}

	if config.GCP.CloudRun.Endpoint != "" && config.GCP.CloudRun.JWT != "" {
		var outputName = "GCPCloudRun"

		client, err := outputs.NewClient(outputName, config.GCP.CloudRun.Endpoint, false, false, config, stats, promStats, statsdClient, dogstatsdClient)

		if err != nil {
			config.GCP.CloudRun.Endpoint = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, outputName)
			outputs.EnabledClients["GCPCloudRun"] = client
		}
	}

	if config.Googlechat.WebhookURL != "" {
		client, err := outputs.NewClient("Googlechat", config.Googlechat.WebhookURL, config.Googlechat.MutualTLS, config.Googlechat.CheckCert, config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.Googlechat.WebhookURL = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "GoogleChat")
			outputs.EnabledClients["GoogleChat"] = client
		}
	}

	if config.Kafka.HostPort != "" && config.Kafka.Topic != "" {
		client, err := outputs.NewKafkaClient(config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.Kafka.HostPort = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "Kafka")
			outputs.EnabledClients["Kafka"] = client
		}
	}

	if config.KafkaRest.Address != "" {
		client, err := outputs.NewClient("KafkaRest", config.KafkaRest.Address, config.KafkaRest.MutualTLS, config.KafkaRest.CheckCert, config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.KafkaRest.Address = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "KafkaRest")
			outputs.EnabledClients["KafkaRest"] = client
		}
	}

	if config.Pagerduty.RoutingKey != "" {
		var url = "https://events.pagerduty.com/v2/enqueue"
		var outputName = "Pagerduty"

		client, err := outputs.NewClient(outputName, url, config.Pagerduty.MutualTLS, config.Pagerduty.CheckCert, config, stats, promStats, statsdClient, dogstatsdClient)

		if err != nil {
			config.Pagerduty.RoutingKey = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, outputName)
			outputs.EnabledClients["Pagerduty"] = client
		}
	}

	if config.Kubeless.Namespace != "" && config.Kubeless.Function != "" {
		client, err := outputs.NewKubelessClient(config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			log.Printf("[ERROR] : Kubeless - %v\n", err)
			config.Kubeless.Namespace = ""
			config.Kubeless.Function = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "Kubeless")
			outputs.EnabledClients["Kubeless"] = client
		}
	}

	if config.WebUI.URL != "" {
		client, err := outputs.NewClient("WebUI", config.WebUI.URL, config.WebUI.MutualTLS, config.WebUI.CheckCert, config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.WebUI.URL = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "WebUI")
			outputs.EnabledClients["WebUI"] = client
		}
	}

	if config.PolicyReport.Enabled {
		client, err := outputs.NewPolicyReportClient(config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.PolicyReport.Enabled = false
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "PolicyReport")
			outputs.EnabledClients["PolicyReport"] = client
		}
	}

	if config.Openfaas.FunctionName != "" {
		client, err := outputs.NewOpenfaasClient(config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			log.Printf("[ERROR] : OpenFaaS - %v\n", err)
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "OpenFaaS")
			outputs.EnabledClients["OpenFaaS"] = client
		}
	}

	if config.Tekton.EventListener != "" {
		client, err := outputs.NewClient("Tekton", config.Tekton.EventListener, false, config.Tekton.CheckCert, config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			log.Printf("[ERROR] : Tekton - %v\n", err)
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "Tekton")
			outputs.EnabledClients["Tekton"] = client
		}
	}

	if config.Rabbitmq.URL != "" && config.Rabbitmq.Queue != "" {
		client, err := outputs.NewRabbitmqClient(config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.Rabbitmq.URL = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "RabbitMQ")
			outputs.EnabledClients["RabbitMQ"] = client
		}
	}

	if config.Wavefront.EndpointType != "" && config.Wavefront.EndpointHost != "" {
		client, err := outputs.NewWavefrontClient(config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			log.Printf("[ERROR] : Wavefront - %v\n", err)
			config.Wavefront.EndpointHost = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "Wavefront")
			outputs.EnabledClients["Wavefront"] = client
		}
	}

	if config.Fission.Function != "" {
		client, err := outputs.NewFissionClient(config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			log.Printf("[ERROR] : Fission - %v\n", err)
		} else {
			// outputs.EnabledOutputs = append(outputs.EnabledOutputs, outputs.Fission)
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, outputs.Fission)
			outputs.EnabledClients["Fission"] = client
		}
	}

	if config.Grafana.HostPort != "" && config.Grafana.APIKey != "" {
		var outputName = "Grafana"
		client, err := outputs.NewClient(outputName, config.Grafana.HostPort+"/api/annotations", config.Grafana.MutualTLS, config.Grafana.CheckCert, config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.Grafana.HostPort = ""
			config.Grafana.APIKey = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, outputName)
			outputs.EnabledClients["Grafana"] = client

		}
	}

	if config.GrafanaOnCall.WebhookURL != "" {
		var outputName = "GrafanaOnCall"
		client, err := outputs.NewClient(outputName, config.GrafanaOnCall.WebhookURL, config.GrafanaOnCall.MutualTLS, config.GrafanaOnCall.CheckCert, config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.GrafanaOnCall.WebhookURL = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, outputName)
			outputs.EnabledClients["GrafanaOnCall"] = client
		}
	}

	if config.Yandex.S3.Bucket != "" {
		client, err := outputs.NewYandexClient(config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.Yandex.S3.Bucket = ""
			log.Printf("[ERROR] : Yandex - %v\n", err)
		} else {
			if config.Yandex.S3.Bucket != "" {
				outputs.EnabledOutputs = append(outputs.EnabledOutputs, "YandexS3")
				outputs.EnabledClients["YandexS3"] = client
			}
		}
	}

	if config.Yandex.DataStreams.StreamName != "" {
		client, err := outputs.NewYandexClient(config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.Yandex.DataStreams.StreamName = ""
			log.Printf("[ERROR] : Yandex - %v\n", err)
		} else {
			if config.Yandex.DataStreams.StreamName != "" {
				outputs.EnabledOutputs = append(outputs.EnabledOutputs, "YandexDataStreams")
				outputs.EnabledClients["YandexDataStreams"] = client
			}
		}
	}

	if config.Syslog.Host != "" {
		client, err := outputs.NewSyslogClient(config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.Syslog.Host = ""
			log.Printf("[ERROR] : Syslog - %v\n", err)
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "Syslog")
			outputs.EnabledClients["Syslog"] = client
		}
	}

	if config.MQTT.Broker != "" {
		client, err := outputs.NewMQTTClient(config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.MQTT.Broker = ""
			log.Printf("[ERROR] : MQTT - %v\n", err)
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "MQTT")
			outputs.EnabledClients["MQTT"] = client
		}
	}

	if config.Zincsearch.HostPort != "" {
		client, err := outputs.NewClient("Zincsearch", config.Zincsearch.HostPort+"/api/"+config.Zincsearch.Index+"/_doc", false, config.Zincsearch.CheckCert, config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.Zincsearch.HostPort = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "Zincsearch")
			outputs.EnabledClients["Zincsearch"] = client
		}
	}

	if config.Gotify.HostPort != "" {
		client, err := outputs.NewClient("Gotify", config.Gotify.HostPort+"/message", false, config.Gotify.CheckCert, config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.Gotify.HostPort = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "Gotify")
			outputs.EnabledClients["Gotify"] = client
		}
	}

	if config.Spyderbat.OrgUID != "" {
		client, err := outputs.NewSpyderbatClient(config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.Spyderbat.OrgUID = ""
			log.Printf("[ERROR] : Spyderbat - %v\n", err)
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "Spyderbat")
			outputs.EnabledClients["Spyderbat"] = client
		}
	}

	if config.TimescaleDB.Host != "" {
		client, err := outputs.NewTimescaleDBClient(config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.TimescaleDB.Host = ""
			log.Printf("[ERROR] : TimescaleDB - %v\n", err)
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "TimescaleDB")
			outputs.EnabledClients["TimescaleDB"] = client
		}
	}

	if config.Redis.Address != "" {
		client, err := outputs.NewRedisClient(config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.Redis.Address = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "Redis")
			outputs.EnabledClients["Redis"] = client
		}
	}

	if config.Telegram.ChatID != "" && config.Telegram.Token != "" {
		var urlFormat = "https://api.telegram.org/bot%s/sendMessage"

		client, err := outputs.NewClient("Telegram", fmt.Sprintf(urlFormat, config.Telegram.Token), false, config.Telegram.CheckCert, config, stats, promStats, statsdClient, dogstatsdClient)

		if err != nil {
			config.Telegram.ChatID = ""
			config.Telegram.Token = ""

			log.Printf("[ERROR] : Telegram - %v\n", err)
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "Telegram")
			outputs.EnabledClients["Telegram"] = client
		}
	}

	if config.N8N.Address != "" {
		client, err := outputs.NewClient("n8n", config.N8N.Address, false, config.N8N.CheckCert, config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.N8N.Address = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "n8n")
			outputs.EnabledClients["n8n"] = client
		}
	}

	if config.OpenObserve.HostPort != "" {
		client, err := outputs.NewClient("OpenObserve", config.OpenObserve.HostPort+"/api/"+config.OpenObserve.OrganizationName+"/"+config.OpenObserve.StreamName+"/_multi", config.OpenObserve.MutualTLS, config.OpenObserve.CheckCert, config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.OpenObserve.HostPort = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "OpenObserve")
			outputs.EnabledClients["OpenObserve"] = client
		}
	}

	if config.Dynatrace.APIToken != "" && config.Dynatrace.APIUrl != "" {
		dynatraceAPIURL := strings.TrimRight(config.Dynatrace.APIUrl, "/") + "/v2/logs/ingest"
		client, err := outputs.NewClient("Dynatrace", dynatraceAPIURL, false, config.Dynatrace.CheckCert, config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.Dynatrace.APIToken = ""
			config.Dynatrace.APIUrl = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "Dynatrace")
			outputs.EnabledClients["Dynatrace"] = client
		}
	}

	log.Printf("[INFO]  : Falco Sidekick version: %s\n", GetVersionInfo().GitVersion)
	log.Printf("[INFO]  : Enabled Outputs : %s\n", outputs.EnabledOutputs)

}

func main() {
	if config.Debug {
		log.Printf("[INFO]  : Debug mode : %v", config.Debug)
	}

	routes := map[string]http.Handler{
		"/":        http.HandlerFunc(mainHandler),
		"/ping":    http.HandlerFunc(pingHandler),
		"/healthz": http.HandlerFunc(healthHandler),
		"/test":    http.HandlerFunc(testHandler),
		"/metrics": promhttp.Handler(),
	}

	mainServeMux := http.NewServeMux()
	var HTTPServeMux *http.ServeMux

	// configure HTTP routes requested by NoTLSPath config
	if config.TLSServer.Deploy {
		HTTPServeMux = http.NewServeMux()
		for _, r := range config.TLSServer.NoTLSPaths {
			handler, ok := routes[r]
			if ok {
				delete(routes, r)
				if config.Debug {
					log.Printf("[DEBUG] : %s is served on http", r)
				}
				HTTPServeMux.Handle(r, handler)
			} else {
				log.Printf("[WARN] : tlsserver.notlspaths has unknown path '%s'", r)
			}
		}
	}

	// configure main server routes
	for r, handler := range routes {
		mainServeMux.Handle(r, handler)
	}

	server := &http.Server{
		Addr:    fmt.Sprintf("%s:%d", config.ListenAddress, config.ListenPort),
		Handler: mainServeMux,
		// Timeouts
		ReadTimeout:       60 * time.Second,
		ReadHeaderTimeout: 60 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	if config.TLSServer.Deploy {
		if config.TLSServer.MutualTLS {
			if config.Debug {
				log.Printf("[DEBUG] : running mTLS server")
			}

			caCert, err := os.ReadFile(config.TLSServer.CaCertFile)
			if err != nil {
				log.Printf("[ERROR] : %v\n", err.Error())
			}
			caCertPool := x509.NewCertPool()
			caCertPool.AppendCertsFromPEM(caCert)

			server.TLSConfig = &tls.Config{
				ClientAuth: tls.RequireAndVerifyClientCert,
				RootCAs:    caCertPool,
				MinVersion: tls.VersionTLS12,
			}
		}

		if config.Debug && !config.TLSServer.MutualTLS {
			log.Printf("[DEBUG] : running TLS server")
		}

		if len(config.TLSServer.NoTLSPaths) != 0 {
			if config.Debug {
				log.Printf("[DEBUG] : running HTTP server for endpoints defined in tlsserver.notlspaths")
			}

			httpServer := &http.Server{
				Addr:    fmt.Sprintf("%s:%d", config.ListenAddress, config.TLSServer.NoTLSPort),
				Handler: HTTPServeMux,
				// Timeouts
				ReadTimeout:       60 * time.Second,
				ReadHeaderTimeout: 60 * time.Second,
				WriteTimeout:      60 * time.Second,
				IdleTimeout:       60 * time.Second,
			}
			log.Printf("[INFO] : Falco Sidekick is up and listening on %s:%d and %s:%d", config.ListenAddress, config.ListenPort, config.ListenAddress, config.TLSServer.NoTLSPort)

			errs := make(chan error, 1)
			go serveTLS(server, errs)
			go serveHTTP(httpServer, errs)
			log.Fatal(<-errs)
		} else {
			log.Printf("[INFO] : Falco Sidekick is up and listening on %s:%d", config.ListenAddress, config.ListenPort)
			if err := server.ListenAndServeTLS(config.TLSServer.CertFile, config.TLSServer.KeyFile); err != nil {
				log.Fatalf("[ERROR] : %v", err.Error())
			}
		}
	} else {
		if config.Debug {
			log.Printf("[DEBUG] : running HTTP server")
		}

		if config.TLSServer.MutualTLS {
			log.Printf("[WARN] : tlsserver.deploy is false but tlsserver.mutualtls is true, change tlsserver.deploy to true to use mTLS")
		}

		if len(config.TLSServer.NoTLSPaths) != 0 {
			log.Printf("[WARN] : tlsserver.deploy is false but tlsserver.notlspaths is not empty, change tlsserver.deploy to true to deploy two servers")
		}

		log.Printf("[INFO]  : Falco Sidekick is up and listening on %s:%d", config.ListenAddress, config.ListenPort)
		if err := server.ListenAndServe(); err != nil {
			log.Fatalf("[ERROR] : %v", err.Error())
		}
	}
}

func serveTLS(server *http.Server, errs chan<- error) {
	errs <- server.ListenAndServeTLS(config.TLSServer.CertFile, config.TLSServer.KeyFile)
}

func serveHTTP(server *http.Server, errs chan<- error) {
	errs <- server.ListenAndServe()
}
