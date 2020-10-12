package controllers

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
)

const defaultTokenPath = "/etc/k8s-vault-issuer/token"

type vaultRootConf struct {
	Cert             []byte
	URL              string
	Token            string
	SecretMountPoint string
}

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
		return vaultRootConf{}, errors.Wrap(err, "read secret")
	}

	vaultConf, ok := rootSecretObj.Data["keyring_vault.conf"]
	if !ok {
		return vaultRootConf{}, errors.New("can't find keyring_vault.conf in secret")
	}
	conf := make(map[string]string)
	for _, f := range strings.Split(string(vaultConf), "\n") {
		kv := strings.Split(f, "=")
		conf[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
	}

	token, err := readVaultToken()
	if err != nil {
		r.Log.Info("can't read vault token from file, trying to get from secret", "err", err)
		token, ok = conf["token"]
		if !ok {
			return vaultRootConf{}, errors.New("can't find vault token in secret and file")
		}
	}

	return vaultRootConf{
		Cert:             rootSecretObj.Data["ca.cert"],
		URL:              conf["vault_url"],
		SecretMountPoint: conf["secret_mount_point"],
		Token:            token,
	}, nil
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
		Address:    vaultConf.URL,
	})
	if err != nil {
		return nil, errors.Wrap(err, "create vault client")
	}
	client.SetToken(vaultConf.Token)
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

func readVaultToken() (string, error) {
	path := defaultTokenPath
	if envPath, ok := os.LookupEnv("VAULT_TOKEN_FILEPATH"); ok {
		path = envPath
	}

	data, err := ioutil.ReadFile(path)
	return string(data), err
}
