package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/jedisct1/dlog"
	"github.com/miekg/dns"
)

type PluginLambdaEntry struct {
	domain      string
	invokeInput lambda.InvokeInput
}

type PluginLambda struct {
	logger  io.Writer
	format  string
	lambdas []PluginLambdaEntry
	sess    *session.Session
	client  *lambda.Lambda
}

func (plugin *PluginLambda) Name() string {
	return "lambda"
}

func (plugin *PluginLambda) Description() string {
	return "Dispatch queries matching specific domains to AWS Lambda functions"
}

func (plugin *PluginLambda) Init(proxy *Proxy) error {
	dlog.Noticef("Loading the set of lambda rules from [%s]", proxy.lambdaFile)
	bin, err := ReadTextFile(proxy.lambdaFile)
	if err != nil {
		return err
	}
	for lineNo, line := range strings.Split(string(bin), "\n") {
		line = TrimAndStripInlineComments(line)
		if len(line) == 0 {
			continue
		}
		domain, lambdaStr, ok := StringTwoFields(line)
		if !ok {
			return fmt.Errorf(
				"Syntax error for a lambda rule at line %d. Expected syntax: %s lambda1,lambda2",
				1+lineNo, domain,
			)
		}

		domain = strings.ToLower(domain)
		config := strings.TrimSpace(lambdaStr)
		q := strings.IndexByte(config, '?')

		var invokeInput lambda.InvokeInput

		if q == -1 {
			invokeInput.FunctionName = &config
		} else {
			name, options := config[:q], config[q+1:]
			invokeInput.FunctionName = &name
			if len(options) > 0 {
				m, err := url.ParseQuery(options)
				if err != nil {
					return fmt.Errorf(
						"Syntax error for a lambda rule with options at line %d. Expected syntax: %s %s?<name>=<value>&...",
						1+lineNo, domain, name,
					)
				}

				for k, v := range m {
					switch k {
					case "InvocationType":
						invokeInput.InvocationType = &v[0]
					case "LogType":
						invokeInput.LogType = &v[0]
					case "Qualifier":
						invokeInput.Qualifier = &v[0]
					default:
						fmt.Printf("Ignored option: `%s'", k)
					}
				}
			}
		}

		plugin.lambdas = append(plugin.lambdas, PluginLambdaEntry{
			domain:      domain,
			invokeInput: invokeInput,
		})
	}

	plugin.logger = Logger(proxy.logMaxSize, proxy.logMaxAge, proxy.logMaxBackups, proxy.lambdaLogFile)
	plugin.format = proxy.lambdaFormat
	plugin.sess = session.Must(session.NewSession())
	plugin.client = lambda.New(plugin.sess, &aws.Config{Region: aws.String(proxy.lambdaRegion)})
	return nil
}

func (plugin *PluginLambda) Drop() error {
	return nil
}

func (plugin *PluginLambda) Reload() error {
	return nil
}

func (plugin *PluginLambda) Eval(pluginsState *PluginsState, msg *dns.Msg) error {
	qName := pluginsState.qName
	qNameLen := len(qName)
	var invokeInput lambda.InvokeInput
	for _, candidate := range plugin.lambdas {
		candidateLen := len(candidate.domain)
		if candidateLen > qNameLen {
			continue
		}
		if qName[qNameLen-candidateLen:] == candidate.domain &&
			(candidateLen == qNameLen || (qName[qNameLen-candidateLen-1] == '.')) {
			invokeInput = candidate.invokeInput
			break
		}
	}

	payload, err := plugin.encode(msg)
	if err != nil {
		dlog.Errorf("[%v] encode request failed: %s", plugin.Name(), err)
		return err
	}

	invokeInput.Payload = payload
	result, err := plugin.client.Invoke(&invokeInput)
	if err != nil {
		dlog.Errorf("[%v] invoke request failed: %s", plugin.Name(), err)
		return err
	}

	if err := plugin.log(pluginsState, msg, result); err != nil {
		return err
	}

	respMsg, err := plugin.decode(result.Payload)
	if err != nil {
		dlog.Errorf("[%v] decode response failed: %s", plugin.Name(), err)
		return err
	}

	pluginsState.synthResponse = respMsg
	pluginsState.action = PluginsActionSynth
	pluginsState.returnCode = PluginsReturnCodeForward
	return nil
}

func (plugin *PluginLambda) encode(msg *dns.Msg) ([]byte, error) {
	// encode DNS message in JSON by rfc8427
	v, err := NewRFC8427Message(msg, 4096)
	if err != nil {
		return nil, err
	}
	return json.Marshal(v)
}

func (plugin *PluginLambda) decode(payload []byte) (*dns.Msg, error) {
	// decode DNS message from JSON by rfc8427
	var v RFC8427Message
	if err := json.Unmarshal(payload, &v); err != nil {
		return nil, err
	}
	return v.Msg()
}

func (plugin *PluginLambda) log(pluginsState *PluginsState, msg *dns.Msg, result *lambda.InvokeOutput) error {
	var clientIPStr string
	if pluginsState.clientProto == "udp" {
		clientIPStr = (*pluginsState.clientAddr).(*net.UDPAddr).IP.String()
	} else {
		clientIPStr = (*pluginsState.clientAddr).(*net.TCPAddr).IP.String()
	}

	qName := pluginsState.qName
	qType, ok := dns.TypeToString[msg.Question[0].Qtype]
	if !ok {
		qType = string(qType)
	}

	var functionError, logResult string

	if result.FunctionError != nil {
		functionError = *result.FunctionError
	}
	if result.LogResult != nil {
		logResult = *result.LogResult
	}

	var line string
	if plugin.format == "tsv" {
		now := time.Now()
		year, month, day := now.Date()
		hour, minute, second := now.Clock()
		tsStr := fmt.Sprintf("[%d-%02d-%02d %02d:%02d:%02d]", year, int(month), day, hour, minute, second)
		line = fmt.Sprintf(
			"%s\t%s\t%s\t%s\t%d\t%s\t%s\t%s\n",
			tsStr, clientIPStr, StringQuote(qName), qType,
			*result.StatusCode,
			*result.ExecutedVersion,
			StringQuote(functionError),
			StringQuote(logResult))
	} else if plugin.format == "ltsv" {
		line = fmt.Sprintf("time:%d\thost:%s\tqname:%s\ttype:%s\tcode:%d\tversion:%s\terror:%s\tlog:%s\n",
			time.Now().Unix(), clientIPStr, StringQuote(qName), qType,
			*result.StatusCode,
			*result.ExecutedVersion,
			StringQuote(functionError),
			StringQuote(logResult))
	} else {
		dlog.Fatalf("Unexpected log format: [%s]", plugin.format)
	}
	if plugin.logger == nil {
		return errors.New("Log file not initialized")
	}
	_, _ = plugin.logger.Write([]byte(line))
	return nil
}
