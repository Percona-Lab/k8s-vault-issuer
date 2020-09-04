package controllers

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"time"

	pxcv1 "github.com/Percona-Lab/k8s-vault-issuer/apis/pxc/v1"
	"github.com/go-logr/logr"
	"github.com/hashicorp/vault/api"
	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func (r *PerconaXtraDBClusterReconciler) processVaultIssueAnnotation(o *pxcv1.PerconaXtraDBCluster, log logr.Logger) error {
	newSecretObj := corev1.Secret{}
	err := r.Client.Get(context.TODO(),
		types.NamespacedName{
			Namespace: o.Namespace,
			Name:      o.Spec.VaultSecretName,
		},
		&newSecretObj,
	)
	if !apierrors.IsNotFound(err) {
		return err
	}
	if err == nil {
		log.Info("issued secret was found, delete annotation")
		return r.deleteAnnotation(o)
	}

	return r.issueVaultToken(o.Spec.VaultSecretName, o.Namespace)
}

func (r *PerconaXtraDBClusterReconciler) issueVaultToken(newSecretName string, customerNamespace string) error {
	rootVaultConf, err := r.vaultRootConf()
	if err != nil {
		return errors.Wrap(err, "get root vault config")
	}
	newData := make(map[string][]byte)

	tr := &http.Transport{}
	if rootVaultConf.Cert != nil {
		newData["ca.cert"] = rootVaultConf.Cert

		certPool, err := x509.SystemCertPool()
		if err != nil {
			return errors.Wrap(err, "failed to get system cert pool")
		}

		ok := certPool.AppendCertsFromPEM(rootVaultConf.Cert)
		if !ok {
			return errors.New("failed to append cert")
		}

		tr.TLSClientConfig = &tls.Config{
			RootCAs: certPool,
		}
	}

	httpClient := &http.Client{
		Timeout:   10 * time.Second,
		Transport: tr,
	}
	cli, err := api.NewClient(&api.Config{
		HttpClient: httpClient,
		Address:    rootVaultConf.Config["vault_url"],
	})
	if err != nil {
		return errors.Wrap(err, "failed to create vault client")
	}

	cli.SetToken(rootVaultConf.Config["token"])
	path := fmt.Sprintf("%s/%s/%s", rootVaultConf.Config["secret_mount_point"], customerNamespace, newSecretName)
	policy := fmt.Sprintf(`
path "%s"
{
  capabilities = ["create", "read", "update", "delete", "list"]
}

path "%s/*"
{
  capabilities = ["create", "read", "update", "delete", "list"]
}
`, path, path)

	policyName := fmt.Sprintf("%s-%s", customerNamespace, newSecretName)
	err = cli.Sys().PutPolicy(policyName, policy)
	if err != nil {
		return errors.Wrap(err, "failed to put policy")
	}

	sec, err := cli.Auth().Token().Create(&api.TokenCreateRequest{
		Policies: []string{policyName},
	})
	if err != nil {
		return errors.Wrap(err, "failed to create token")
	}

	token := sec.Auth.ClientToken
	newData["keyring_vault.conf"] = []byte(
		fmt.Sprintf(`
token = %s
vault_url = %s
secret_mount_point = %s
vault_ca = %s`,
			token,
			rootVaultConf.Config["vault_url"],
			path,
			rootVaultConf.Config["vault_ca"],
		))

	secretObj := corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      newSecretName,
			Namespace: customerNamespace,
		},
		Data: newData,
		Type: corev1.SecretTypeOpaque,
	}

	err = r.Client.Create(context.TODO(), &secretObj)
	if err != nil {
		return errors.Wrap(err, "create token secret")
	}

	return nil
}
