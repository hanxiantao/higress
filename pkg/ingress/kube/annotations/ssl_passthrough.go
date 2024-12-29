package annotations

import (
	"fmt"

	networking "istio.io/api/networking/v1alpha3"
	"istio.io/istio/pkg/config/protocol"
)

var (
	_ Parser                = &sslPassthrough{}
	_ GatewayHandler        = &sslPassthrough{}
	_ VirtualServiceHandler = &sslPassthrough{}
)

const sslPassthroughAnnotation = "ssl-passthrough"

type SslPassthroughConfig struct {
}

type sslPassthrough struct{}

func (s sslPassthrough) Parse(annotations Annotations, config *Ingress, globalContext *GlobalContext) error {
	if !needSslPassthroughConfig(annotations) {
		return nil
	}
	config.SslPassthroughConfig = &SslPassthroughConfig{}
	return nil
}

func (s sslPassthrough) ApplyGateway(gateway *networking.Gateway, config *Ingress) {
	if config.SslPassthroughConfig == nil {
		return
	}
	hosts := gateway.Servers[0].Hosts

	gateway.Servers = append(gateway.Servers, &networking.Server{
		Port: &networking.Port{
			Number:   443,
			Protocol: string(protocol.HTTPS),
			//Name:     common.CreateConvertedName("https-443-ingress", config.Meta.ClusterId.String()),
		},
		Hosts: hosts,
		Tls: &networking.ServerTLSSettings{
			Mode: networking.ServerTLSSettings_PASSTHROUGH,
		},
	})
}

func (s sslPassthrough) ApplyVirtualServiceHandler(virtualService *networking.VirtualService, config *Ingress) {
	if config.SslPassthroughConfig == nil {
		return
	}
	http := virtualService.Http
	fmt.Println(http)
}

func needSslPassthroughConfig(annotations Annotations) bool {
	return annotations[buildNginxAnnotationKey(sslPassthroughAnnotation)] == "true"
}
