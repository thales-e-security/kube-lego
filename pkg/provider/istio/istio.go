package istio

import (
	"github.com/jetstack/kube-lego/pkg/ingress"
	kubelego "github.com/jetstack/kube-lego/pkg/kubelego_const"
	"github.com/jetstack/kube-lego/pkg/service"

	"sort"

	"github.com/Sirupsen/logrus"
	k8sExtensions "k8s.io/client-go/pkg/apis/extensions/v1beta1"
)

var _ kubelego.IngressProvider = &Istio{}

type Istio struct {
	kubelego kubelego.KubeLego
	hosts    map[string]bool
	ingress  kubelego.Ingress
	service  kubelego.Service
}

func New(kl kubelego.KubeLego) *Istio {
	return &Istio{
		kubelego: kl,
		hosts:    map[string]bool{},
	}
}

func (p *Istio) Log() (log *logrus.Entry) {
	return p.kubelego.Log().WithField("context", "provider").WithField("provider", "istio")
}

func (p *Istio) Reset() error {
	p.Log().Debug("reset")
	p.hosts = map[string]bool{}
	return nil
}

func (p *Istio) Finalize() error {
	p.Log().Debug("finalize")

	if p.ingress == nil {
		p.ingress = ingress.New(p.kubelego, p.kubelego.LegoNamespace(), p.kubelego.LegoIngressNameIstio())
	}
	if p.service == nil {
		p.service = service.New(p.kubelego, p.kubelego.LegoNamespace(), p.kubelego.LegoServiceNameIstio())
	}

	if len(p.hosts) < 1 {
		p.Log().Info("disable provider no TLS hosts found")

		err := p.service.Delete()
		if err != nil {
			p.Log().Error(err)
		}

		err = p.ingress.Delete()
		if err != nil {
			p.Log().Error(err)
		}
	} else {
		err := p.updateService()
		if err != nil {
			p.Log().Error(err)
		}
		err = p.updateIngress()
		if err != nil {
			p.Log().Error(err)
		}
	}

	p.service = nil
	p.ingress = nil
	return nil
}

func (p *Istio) getHosts() (hosts []string) {
	for host, enabled := range p.hosts {
		if enabled {
			hosts = append(hosts, host)
		}
	}
	sort.Strings(hosts)
	return
}

func (p *Istio) updateService() error {

	p.service.SetKubeLegoSpec()
	return p.service.Save()

}

func (p *Istio) updateIngress() error {

	ing := p.ingress.Object()
	rules := []k8sExtensions.IngressRule{}
	paths := []k8sExtensions.HTTPIngressPath{
		k8sExtensions.HTTPIngressPath{
			Path: kubelego.AcmeHttpChallengePath,
			Backend: k8sExtensions.IngressBackend{
				ServiceName: p.kubelego.LegoServiceNameIstio(),
				ServicePort: p.kubelego.LegoHTTPPort(),
			},
		},
	}
	ruleValue := k8sExtensions.IngressRuleValue{
		&k8sExtensions.HTTPIngressRuleValue{
			Paths: paths,
		},
	}
	for _, host := range p.getHosts() {
		rules = append(rules, k8sExtensions.IngressRule{
			Host:             host,
			IngressRuleValue: ruleValue,
		})
	}

	ing.Annotations = map[string]string{
		kubelego.AnnotationIngressChallengeEndpoints: "true",
		kubelego.AnnotationSslRedirect:               "false",
		// TODO: use the ingres class as specified on the ingress we are
		// requesting a certificate for
		kubelego.AnnotationIngressClass:         p.kubelego.LegoDefaultIngressClass(),
		kubelego.AnnotationIngressProvider:      p.kubelego.LegoDefaultIngressProvider(),
		kubelego.AnnotationWhitelistSourceRange: "0.0.0.0/0,::/0",
	}

	ing.Spec = k8sExtensions.IngressSpec{
		Rules: rules,
	}

	return p.ingress.Save()
}

func (p *Istio) Process(ing kubelego.Ingress) error {
	for _, tls := range ing.Tls() {
		for _, host := range tls.Hosts() {
			p.hosts[host] = true
		}
	}
	return nil
}
