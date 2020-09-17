package controllers

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/hashicorp/vault/api"
	"github.com/pkg/errors"
)

func (r *PerconaXtraDBClusterReconciler) vaultConfFrom(namespace, secretName string) (vaultRootConf, error) {
	rootSecretObj := corev1.Secret{}
	err := r.Client.Get(context.TODO(),
		types.NamespacedName{
			Namespace: namespace,
			Name:      secretName,
		},
		&rootSecretObj,
	)
	if err != nil {
		return vaultRootConf{}, err
	}

	res := vaultRootConf{
		Cert:   rootSecretObj.Data["ca.cert"],
		Config: make(map[string]string),
	}

	data := string(rootSecretObj.Data["keyring_vault.conf"])
	for _, f := range strings.Split(data, "\n") {
		kv := strings.Split(f, "=")
		res.Config[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
	}
	return res, nil
}

func vaultClient(vaultConf vaultRootConf) (*api.Client, error) {
	httpClient := &http.Client{
		Timeout: 10 * time.Second,
	}
	if vaultConf.Cert != nil {
		tr, err := vaultTransport(vaultConf.Cert)
		if err != nil {
			return nil, errors.Wrap(err, "create vault transport")
		}
		httpClient.Transport = tr
	}

	client, err := api.NewClient(&api.Config{
		HttpClient: httpClient,
		Address:    vaultConf.Config["vault_url"],
	})

	if err != nil {
		return nil, errors.Wrap(err, "create vault client")
	}
	client.SetToken(vaultConf.Config["token"])
	return client, nil
}

func vaultTransport(cert []byte) (http.RoundTripper, error) {
	certPool, err := x509.SystemCertPool()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get system cert pool")
	}

	ok := certPool.AppendCertsFromPEM(cert)
	if !ok {
		return nil, errors.New("failed to append cert")
	}

	return &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs: certPool,
		},
	}, nil
}
