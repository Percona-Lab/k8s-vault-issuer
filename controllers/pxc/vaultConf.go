package controllers

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/pkg/errors"
)

func vaultClient(vaultConf vaultRootConf) (*api.Client, error) {
	httpClient := &http.Client{
		Timeout: 10 * time.Second,
	}
	if vaultConf.Cert != nil {
		tr, err := getVaultTransport(vaultConf.Cert)
		if err != nil {
			return nil, err
		}
		httpClient.Transport = tr
	}
	client, err := api.NewClient(&api.Config{
		HttpClient: httpClient,
		Address:    vaultConf.Config["vault_url"],
	})
	if err != nil {
		return nil, err
	}
	client.SetToken(vaultConf.Config["token"])
	return client, nil
}

func getVaultTransport(cert []byte) (http.RoundTripper, error) {
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
