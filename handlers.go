package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"text/template"
	"time"

	"github.com/falcosecurity/falcosidekick/outputs"
	"github.com/falcosecurity/falcosidekick/types"
	"github.com/google/uuid"
)

const testRule string = "Test rule"

// mainHandler is Falco Sidekick main handler (default).
func mainHandler(w http.ResponseWriter, r *http.Request) {
	stats.Requests.Add("total", 1)
	nullClient.CountMetric("total", 1, []string{})

	if r.Body == nil {
		http.Error(w, "Please send a valid request body", http.StatusBadRequest)
		stats.Requests.Add("rejected", 1)
		promStats.Inputs.With(map[string]string{"source": "requests", "status": "rejected"}).Inc()
		nullClient.CountMetric("inputs.requests.rejected", 1, []string{"error:nobody"})

		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Please send with post http method", http.StatusBadRequest)
		stats.Requests.Add("rejected", 1)
		promStats.Inputs.With(map[string]string{"source": "requests", "status": "rejected"}).Inc()
		nullClient.CountMetric("inputs.requests.rejected", 1, []string{"error:nobody"})

		return
	}

	falcopayload, err := newFalcoPayload(r.Body)
	if err != nil || !falcopayload.Check() {
		http.Error(w, "Please send a valid request body", http.StatusBadRequest)
		stats.Requests.Add("rejected", 1)
		promStats.Inputs.With(map[string]string{"source": "requests", "status": "rejected"}).Inc()
		nullClient.CountMetric("inputs.requests.rejected", 1, []string{"error:invalidjson"})

		return
	}

	nullClient.CountMetric("inputs.requests.accepted", 1, []string{})
	stats.Requests.Add("accepted", 1)
	promStats.Inputs.With(map[string]string{"source": "requests", "status": "accepted"}).Inc()
	forwardEvent(falcopayload)
}

// pingHandler is a simple handler to test if daemon is UP.
func pingHandler(w http.ResponseWriter, r *http.Request) {
	// #nosec G104 nothing to be done if the following fails
	w.Write([]byte("pong\n"))
}

// healthHandler is a simple handler to test if daemon is UP.
func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "application/json")
	// #nosec G104 nothing to be done if the following fails
	w.Write([]byte(`{"status": "ok"}`))
}

// testHandler sends a test event to all enabled outputs.
func testHandler(w http.ResponseWriter, r *http.Request) {
	r.Body = io.NopCloser(bytes.NewReader([]byte(`{"output":"This is a test from falcosidekick","priority":"Debug","hostname": "falcosidekick", "rule":"Test rule", "time":"` + time.Now().UTC().Format(time.RFC3339) + `","output_fields": {"proc.name":"falcosidekick","user.name":"falcosidekick"}, "tags":["test","example"]}`)))
	mainHandler(w, r)
}

func newFalcoPayload(payload io.Reader) (types.FalcoPayload, error) {
	var falcopayload types.FalcoPayload

	d := json.NewDecoder(payload)
	d.UseNumber()

	err := d.Decode(&falcopayload)
	if err != nil {
		return types.FalcoPayload{}, err
	}

	if len(config.Customfields) > 0 {
		if falcopayload.OutputFields == nil {
			falcopayload.OutputFields = make(map[string]interface{})
		}
		for key, value := range config.Customfields {
			falcopayload.OutputFields[key] = value
		}
	}

	if falcopayload.Source == "" {
		falcopayload.Source = "syscalls"
	}

	falcopayload.UUID = uuid.New().String()

	var kn, kp string
	for i, j := range falcopayload.OutputFields {
		if j != nil {
			if i == "k8s.ns.name" {
				kn = j.(string)
			}
			if i == "k8s.pod.name" {
				kp = j.(string)
			}
		}
	}

	if len(config.Templatedfields) > 0 {
		if falcopayload.OutputFields == nil {
			falcopayload.OutputFields = make(map[string]interface{})
		}
		for key, value := range config.Templatedfields {
			tmpl, err := template.New("").Parse(value)
			if err != nil {
				log.Printf("[ERROR] : Parsing error for templated field '%v': %v\n", key, err)
				continue
			}
			v := new(bytes.Buffer)
			if err := tmpl.Execute(v, falcopayload.OutputFields); err != nil {
				log.Printf("[ERROR] : Parsing error for templated field '%v': %v\n", key, err)
			}
			falcopayload.OutputFields[key] = v.String()
		}
	}

	nullClient.CountMetric("falco.accepted", 1, []string{"priority:" + falcopayload.Priority.String()})
	stats.Falco.Add(strings.ToLower(falcopayload.Priority.String()), 1)
	promLabels := map[string]string{"rule": falcopayload.Rule, "priority": falcopayload.Priority.String(), "k8s_ns_name": kn, "k8s_pod_name": kp}
	if falcopayload.Hostname != "" {
		promLabels["hostname"] = falcopayload.Hostname
	}

	for key, value := range config.Customfields {
		if regPromLabels.MatchString(key) {
			promLabels[key] = value
		}
	}
	for _, i := range config.Prometheus.ExtraLabelsList {
		promLabels[strings.ReplaceAll(i, ".", "_")] = ""
		for key, value := range falcopayload.OutputFields {
			if key == i && regPromLabels.MatchString(strings.ReplaceAll(key, ".", "_")) {
				switch value.(type) {
				case string:
					promLabels[strings.ReplaceAll(key, ".", "_")] = fmt.Sprintf("%v", value)
				default:
					continue
				}
			}
		}
	}
	promStats.Falco.With(promLabels).Inc()

	if config.BracketReplacer != "" {
		for i, j := range falcopayload.OutputFields {
			if strings.Contains(i, "[") {
				falcopayload.OutputFields[strings.ReplaceAll(strings.ReplaceAll(i, "]", ""), "[", config.BracketReplacer)] = j
				delete(falcopayload.OutputFields, i)
			}
		}
	}

	if config.Debug {
		body, _ := json.Marshal(falcopayload)
		log.Printf("[DEBUG] : Falco's payload : %v\n", string(body))
	}

	return falcopayload, nil
}

func forwardEvent(falcopayload types.FalcoPayload) {
	if config.Slack.WebhookURL != "" && (falcopayload.Priority >= types.Priority(config.Slack.MinimumPriority) || falcopayload.Rule == testRule) {
		go outputs.EnabledClients["Slack"].SlackPost(falcopayload) // older slackClient
	}

	if config.Cliq.WebhookURL != "" && (falcopayload.Priority >= types.Priority(config.Cliq.MinimumPriority) || falcopayload.Rule == testRule) {
		go outputs.EnabledClients["Cliq"].CliqPost(falcopayload)
	}

	if config.Rocketchat.WebhookURL != "" && (falcopayload.Priority >= types.Priority(config.Rocketchat.MinimumPriority) || falcopayload.Rule == testRule) {
		go outputs.EnabledClients["Rocketchat"].RocketchatPost(falcopayload)
	}

	if config.Mattermost.WebhookURL != "" && (falcopayload.Priority >= types.Priority(config.Mattermost.MinimumPriority) || falcopayload.Rule == testRule) {
		go outputs.EnabledClients["Mattermost"].MattermostPost(falcopayload)
	}

	if config.Teams.WebhookURL != "" && (falcopayload.Priority >= types.Priority(config.Teams.MinimumPriority) || falcopayload.Rule == testRule) {
		go outputs.EnabledClients["Teams"].TeamsPost(falcopayload)
	}

	if config.Datadog.APIKey != "" && (falcopayload.Priority >= types.Priority(config.Datadog.MinimumPriority) || falcopayload.Rule == testRule) {
		go outputs.EnabledClients["Datadog"].DatadogPost(falcopayload)
	}

	if config.Discord.WebhookURL != "" && (falcopayload.Priority >= types.Priority(config.Discord.MinimumPriority) || falcopayload.Rule == testRule) {
		go outputs.EnabledClients["Discord"].DiscordPost(falcopayload)
	}

	if config.Alertmanager.HostPort != "" && (falcopayload.Priority >= types.Priority(config.Alertmanager.MinimumPriority) || falcopayload.Rule == testRule) {
		go outputs.EnabledClients["AlertManager"].AlertmanagerPost(falcopayload)
	}

	if config.Elasticsearch.HostPort != "" && (falcopayload.Priority >= types.Priority(config.Elasticsearch.MinimumPriority) || falcopayload.Rule == testRule) {
		go outputs.EnabledClients["Elasticsearch"].ElasticsearchPost(falcopayload)
	}

	if config.Influxdb.HostPort != "" && (falcopayload.Priority >= types.Priority(config.Influxdb.MinimumPriority) || falcopayload.Rule == testRule) {
		go outputs.EnabledClients["Influxdb"].InfluxdbPost(falcopayload)
	}

	if config.Loki.HostPort != "" && (falcopayload.Priority >= types.Priority(config.Loki.MinimumPriority) || falcopayload.Rule == testRule) {
		go outputs.EnabledClients["Loki"].LokiPost(falcopayload)
	}

	if config.Nats.HostPort != "" && (falcopayload.Priority >= types.Priority(config.Nats.MinimumPriority) || falcopayload.Rule == testRule) {
		go outputs.EnabledClients["NATS"].NatsPublish(falcopayload)
	}

	if config.Stan.HostPort != "" && config.Stan.ClusterID != "" && config.Stan.ClientID != "" && (falcopayload.Priority >= types.Priority(config.Stan.MinimumPriority) || falcopayload.Rule == testRule) {
		go outputs.EnabledClients["STAN"].StanPublish(falcopayload)
	}

	if config.AWS.Lambda.FunctionName != "" && (falcopayload.Priority >= types.Priority(config.AWS.Lambda.MinimumPriority) || falcopayload.Rule == testRule) {
		go outputs.EnabledClients["AWSLambda"].InvokeLambda(falcopayload)
	}

	if config.AWS.SQS.URL != "" && (falcopayload.Priority >= types.Priority(config.AWS.SQS.MinimumPriority) || falcopayload.Rule == testRule) {
		go outputs.EnabledClients["AWSSQS"].SendMessage(falcopayload)
	}

	if config.AWS.SNS.TopicArn != "" && (falcopayload.Priority >= types.Priority(config.AWS.SNS.MinimumPriority) || falcopayload.Rule == testRule) {
		go outputs.EnabledClients["AWSSNS"].PublishTopic(falcopayload)
	}

	if config.AWS.CloudWatchLogs.LogGroup != "" && (falcopayload.Priority >= types.Priority(config.AWS.CloudWatchLogs.MinimumPriority) || falcopayload.Rule == testRule) {
		go outputs.EnabledClients["AWSCloudWatchLogs"].SendCloudWatchLog(falcopayload)
	}

	if config.AWS.S3.Bucket != "" && (falcopayload.Priority >= types.Priority(config.AWS.S3.MinimumPriority) || falcopayload.Rule == testRule) {
		go outputs.EnabledClients["AWSS3"].UploadS3(falcopayload)
	}

	if (config.AWS.SecurityLake.Bucket != "" && config.AWS.SecurityLake.Region != "" && config.AWS.SecurityLake.AccountID != "" && config.AWS.SecurityLake.Prefix != "") && (falcopayload.Priority >= types.Priority(config.AWS.SecurityLake.MinimumPriority) || falcopayload.Rule == testRule) {
		go outputs.EnabledClients["AWSSecurityLake"].EnqueueSecurityLake(falcopayload)
	}

	if config.AWS.Kinesis.StreamName != "" && (falcopayload.Priority >= types.Priority(config.AWS.Kinesis.MinimumPriority) || falcopayload.Rule == testRule) {
		go outputs.EnabledClients["AWSKinesis"].PutRecord(falcopayload)
	}

	if config.SMTP.HostPort != "" && (falcopayload.Priority >= types.Priority(config.SMTP.MinimumPriority) || falcopayload.Rule == testRule) {
		go outputs.EnabledClients["SMTP"].SendMail(falcopayload)
	}

	if config.Opsgenie.APIKey != "" && (falcopayload.Priority >= types.Priority(config.Opsgenie.MinimumPriority) || falcopayload.Rule == testRule) {
		go outputs.EnabledClients["Opsgenie"].OpsgeniePost(falcopayload)
	}

	if config.Webhook.Address != "" && (falcopayload.Priority >= types.Priority(config.Webhook.MinimumPriority) || falcopayload.Rule == testRule) {
		go outputs.EnabledClients["Webhook"].WebhookPost(falcopayload)
	}

	if config.NodeRed.Address != "" && (falcopayload.Priority >= types.Priority(config.NodeRed.MinimumPriority) || falcopayload.Rule == testRule) {
		go outputs.EnabledClients["NodeRed"].NodeRedPost(falcopayload)
	}

	if config.CloudEvents.Address != "" && (falcopayload.Priority >= types.Priority(config.CloudEvents.MinimumPriority) || falcopayload.Rule == testRule) {
		go outputs.EnabledClients["CloudEvents"].CloudEventsSend(falcopayload)
	}

	if config.Azure.EventHub.Name != "" && (falcopayload.Priority >= types.Priority(config.Azure.EventHub.MinimumPriority) || falcopayload.Rule == testRule) {
		go outputs.EnabledClients["EventHub"].EventHubPost(falcopayload)
	}

	if config.GCP.PubSub.ProjectID != "" && config.GCP.PubSub.Topic != "" && (falcopayload.Priority >= types.Priority(config.GCP.PubSub.MinimumPriority) || falcopayload.Rule == testRule) {
		go outputs.EnabledClients["GCPPubSub"].GCPPublishTopic(falcopayload)
	}

	if config.GCP.CloudFunctions.Name != "" && (falcopayload.Priority >= types.Priority(config.GCP.CloudFunctions.MinimumPriority) || falcopayload.Rule == testRule) {
		go outputs.EnabledClients["GCPCloudFunctions"].GCPCallCloudFunction(falcopayload)
	}

	if config.GCP.CloudRun.Endpoint != "" && (falcopayload.Priority >= types.Priority(config.GCP.CloudRun.MinimumPriority) || falcopayload.Rule == testRule) {
		go outputs.EnabledClients["GCPCloudRun"].CloudRunFunctionPost(falcopayload)
	}

	if config.GCP.Storage.Bucket != "" && (falcopayload.Priority >= types.Priority(config.GCP.Storage.MinimumPriority) || falcopayload.Rule == testRule) {
		go outputs.EnabledClients["GCPStorage"].UploadGCS(falcopayload)
	}

	if config.Googlechat.WebhookURL != "" && (falcopayload.Priority >= types.Priority(config.Googlechat.MinimumPriority) || falcopayload.Rule == testRule) {
		go outputs.EnabledClients["Googlechat"].GooglechatPost(falcopayload)
	}

	if config.Kafka.HostPort != "" && (falcopayload.Priority >= types.Priority(config.Kafka.MinimumPriority) || falcopayload.Rule == testRule) {
		go outputs.EnabledClients["Kafka"].KafkaProduce(falcopayload)
	}

	if config.KafkaRest.Address != "" && (falcopayload.Priority >= types.Priority(config.KafkaRest.MinimumPriority) || falcopayload.Rule == testRule) {
		go outputs.EnabledClients["KafkaRest"].KafkaRestPost(falcopayload)
	}

	if config.Pagerduty.RoutingKey != "" && (falcopayload.Priority >= types.Priority(config.Pagerduty.MinimumPriority) || falcopayload.Rule == testRule) {
		go outputs.EnabledClients["Pagerduty"].PagerdutyPost(falcopayload)
	}

	if config.Kubeless.Namespace != "" && config.Kubeless.Function != "" && (falcopayload.Priority >= types.Priority(config.Kubeless.MinimumPriority) || falcopayload.Rule == testRule) {
		go outputs.EnabledClients["Kubeless"].KubelessCall(falcopayload)
	}

	if config.Openfaas.FunctionName != "" && (falcopayload.Priority >= types.Priority(config.Openfaas.MinimumPriority) || falcopayload.Rule == testRule) {
		go outputs.EnabledClients["OpenFaaS"].OpenfaasCall(falcopayload)
	}

	if config.Tekton.EventListener != "" && (falcopayload.Priority >= types.Priority(config.Tekton.MinimumPriority) || falcopayload.Rule == testRule) {
		go outputs.EnabledClients["Tekton"].TektonPost(falcopayload)
	}

	if config.Rabbitmq.URL != "" && config.Rabbitmq.Queue != "" && (falcopayload.Priority >= types.Priority(config.Openfaas.MinimumPriority) || falcopayload.Rule == testRule) {
		go outputs.EnabledClients["RabbitMQ"].Publish(falcopayload)
	}

	if config.Wavefront.EndpointHost != "" && config.Wavefront.EndpointType != "" && (falcopayload.Priority >= types.Priority(config.Wavefront.MinimumPriority) || falcopayload.Rule == testRule) {
		go outputs.EnabledClients["Wavefront"].WavefrontPost(falcopayload)
	}

	if config.Grafana.HostPort != "" && (falcopayload.Priority >= types.Priority(config.Grafana.MinimumPriority) || falcopayload.Rule == testRule) {
		go outputs.EnabledClients["Grafana"].GrafanaPost(falcopayload)
	}

	if config.GrafanaOnCall.WebhookURL != "" && (falcopayload.Priority >= types.Priority(config.GrafanaOnCall.MinimumPriority) || falcopayload.Rule == testRule) {
		go outputs.EnabledClients["GrafanaOnCall"].GrafanaOnCallPost(falcopayload)
	}

	if config.WebUI.URL != "" {
		go outputs.EnabledClients["WebUI"].WebUIPost(falcopayload)
	}

	if config.Fission.Function != "" && (falcopayload.Priority >= types.Priority(config.Fission.MinimumPriority) || falcopayload.Rule == testRule) {
		go outputs.EnabledClients["Fission"].FissionCall(falcopayload)
	}
	if config.PolicyReport.Enabled && (falcopayload.Priority >= types.Priority(config.PolicyReport.MinimumPriority)) {
		go outputs.EnabledClients["PolicyReport"].UpdateOrCreatePolicyReport(falcopayload)
	}

	if config.Yandex.S3.Bucket != "" && (falcopayload.Priority >= types.Priority(config.Yandex.S3.MinimumPriority) || falcopayload.Rule == testRule) {
		go outputs.EnabledClients["YandexS3"].UploadYandexS3(falcopayload)
	}

	if config.Yandex.DataStreams.StreamName != "" && (falcopayload.Priority >= types.Priority(config.Yandex.DataStreams.MinimumPriority) || falcopayload.Rule == testRule) {
		go outputs.EnabledClients["YandexDataStreams"].UploadYandexDataStreams(falcopayload)
	}

	if config.Syslog.Host != "" && (falcopayload.Priority >= types.Priority(config.Syslog.MinimumPriority) || falcopayload.Rule == testRule) {
		go outputs.EnabledClients["Syslog"].SyslogPost(falcopayload)
	}

	if config.MQTT.Broker != "" && (falcopayload.Priority >= types.Priority(config.MQTT.MinimumPriority) || falcopayload.Rule == testRule) {
		go outputs.EnabledClients["MQTT"].MQTTPublish(falcopayload)
	}

	if config.Zincsearch.HostPort != "" && (falcopayload.Priority >= types.Priority(config.Zincsearch.MinimumPriority) || falcopayload.Rule == testRule) {
		go outputs.EnabledClients["Zincsearch"].ZincsearchPost(falcopayload)
	}

	if config.Gotify.HostPort != "" && (falcopayload.Priority >= types.Priority(config.Gotify.MinimumPriority) || falcopayload.Rule == testRule) {
		go outputs.EnabledClients["Gotify"].GotifyPost(falcopayload)
	}

	if config.Spyderbat.OrgUID != "" && (falcopayload.Priority >= types.Priority(config.Spyderbat.MinimumPriority) || falcopayload.Rule == testRule) {
		go outputs.EnabledClients["Spyderbat"].SpyderbatPost(falcopayload)
	}

	if config.TimescaleDB.Host != "" && (falcopayload.Priority >= types.Priority(config.TimescaleDB.MinimumPriority) || falcopayload.Rule == testRule) {
		go outputs.EnabledClients["TimescaleDB"].TimescaleDBPost(falcopayload)
	}

	if config.Redis.Address != "" && (falcopayload.Priority >= types.Priority(config.Redis.MinimumPriority) || falcopayload.Rule == testRule) {
		go outputs.EnabledClients["Redis"].RedisPost(falcopayload)
	}

	if config.Telegram.ChatID != "" && config.Telegram.Token != "" && (falcopayload.Priority >= types.Priority(config.Telegram.MinimumPriority) || falcopayload.Rule == testRule) {
		go outputs.EnabledClients["Telegram"].TelegramPost(falcopayload)
	}

	if config.N8N.Address != "" && (falcopayload.Priority >= types.Priority(config.N8N.MinimumPriority) || falcopayload.Rule == testRule) {
		go outputs.EnabledClients["n8n"].N8NPost(falcopayload)
	}

	if config.OpenObserve.HostPort != "" && (falcopayload.Priority >= types.Priority(config.OpenObserve.MinimumPriority) || falcopayload.Rule == testRule) {
		go outputs.EnabledClients["OpenObserve"].OpenObservePost(falcopayload)
	}

	if config.Dynatrace.APIToken != "" && config.Dynatrace.APIUrl != "" && (falcopayload.Priority >= types.Priority(config.Dynatrace.MinimumPriority) || falcopayload.Rule == testRule) {
		go outputs.EnabledClients["Dynatrace"].DynatracePost(falcopayload)
	}
}
