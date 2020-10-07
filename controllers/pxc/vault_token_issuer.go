package controllers

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	"github.com/hashicorp/vault/api"
	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	pxcv1 "github.com/Percona-Lab/k8s-vault-issuer/apis/pxc/v1"
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
		return r.deleteAnnotation(o, "percona.com/issue-vault-token")
	}

	return r.issueVaultToken(o.Spec.VaultSecretName, o.Namespace)
}

func (r *PerconaXtraDBClusterReconciler) issueVaultToken(newSecretName string, customerNamespace string) error {
	rootVaultConf, err := r.vaultConfFrom(r.Namespace, r.RootVaultSecretName)
	if err != nil {
		return errors.Wrap(err, "get root vault config")
	}

	cl, err := vaultClient(rootVaultConf)
	if err != nil {
		return errors.Wrap(err, "create vault client")
	}

	newData := make(map[string][]byte)

	if rootVaultConf.Cert != nil {
		newData["ca.cert"] = rootVaultConf.Cert
	}

	path := fmt.Sprintf("%s/%s/%s", rootVaultConf.SecretMountPoint, customerNamespace, newSecretName)
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
	err = cl.Sys().PutPolicy(policyName, policy)
	if err != nil {
		return errors.Wrap(err, "failed to put policy")
	}

	sec, err := cl.Auth().Token().Create(&api.TokenCreateRequest{
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
			rootVaultConf.URL,
			path,
			rootVaultConf.Cert,
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
