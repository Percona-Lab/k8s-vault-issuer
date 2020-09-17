package controllers

import (
	"context"
	"fmt"
	"strings"

	pxcv1 "github.com/Percona-Lab/k8s-vault-issuer/apis/pxc/v1"
	"github.com/pkg/errors"
	"k8s.io/apimachinery/pkg/types"
)

func (r *PerconaXtraDBClusterReconciler) processTransferVaultKeys(currClusterCR *pxcv1.PerconaXtraDBCluster, clusters []string) error {
	currClusterName := currClusterCR.Name + "." + currClusterCR.Namespace
	for _, v := range clusters {
		splittedName := strings.Split(v, ".")
		if len(splittedName) != 2 {
			return errors.New("invalid source cluster name, plaease use format clusterName.namespace")
		}

		clusterName, clusterNamespace := splittedName[0], splittedName[1]

		srcClusterCR := &pxcv1.PerconaXtraDBCluster{}
		err := r.Client.Get(context.TODO(),
			types.NamespacedName{
				Namespace: clusterNamespace,
				Name:      clusterName,
			}, srcClusterCR)
		if err != nil {
			return errors.Wrapf(err, "get cluster srcClusterCR from namespace %s", v)
		}

		values, ok := srcClusterCR.Annotations["percona.com/allow-transition-key-transfer"]
		if !ok {
			return errors.Errorf("no percona.com/allow-transition-key-transfer annotation found at cluster %s", v)
		}

		allowed := false
		for _, allowedClusters := range strings.Split(values, ",") {
			if allowedClusters == currClusterName {
				allowed = true
				break
			}
		}

		if !allowed {
			return fmt.Errorf("cluster %s is not allowing copying keys for cluster %s ", v, currClusterName)
		}

		if err := r.transferTransitionKeys(srcClusterCR, currClusterCR); err != nil {
			return errors.Wrapf(err, "transfer transition key from:%s to:%s", v, currClusterCR.Namespace)
		}
	}
	return r.deleteAnnotation(currClusterCR, "percona.com/vault-transfer-keys")
}

func (r *PerconaXtraDBClusterReconciler) transferTransitionKeys(from, to *pxcv1.PerconaXtraDBCluster) error {
	srcVaultConf, err := r.vaultConfFrom(from.Namespace, from.Spec.VaultSecretName)
	if err != nil {
		return errors.Wrapf(err, "get vault conf from namespace: %s, secretName: %s", from.Namespace, from.Spec.VaultSecretName)
	}

	targetVaultConf, err := r.vaultConfFrom(to.Namespace, to.Spec.VaultSecretName)
	if err != nil {
		return errors.Wrapf(err, "get vault conf from namespace: %s, secretName: %s", to.Namespace, to.Spec.VaultSecretName)
	}

	vaultSecretFrom := srcVaultConf.Config["secret_mount_point"]
	vaultSecretTo := targetVaultConf.Config["secret_mount_point"]

	r.Log.Info("Copying transition keys", "from", vaultSecretFrom, "to", vaultSecretTo)

	vaultRootConf, err := r.vaultConfFrom(r.Namespace, r.RootVaultSecretName)
	if err != nil {
		return errors.Wrap(err, "get root conf")
	}

	vaultClient, err := vaultClient(vaultRootConf)
	if err != nil {
		return errors.Wrap(err, "setup vault client")
	}

	logicalClient := vaultClient.Logical()
	secretList, err := logicalClient.List(vaultSecretFrom + "/backup/")
	if err != nil {
		return errors.Wrap(err, "list backup secretList")
	}

	if secretList == nil || secretList.Data == nil || secretList.Data["keys"] == nil {
		return errors.New("no transition keys found")
	}

	for _, backupUIDInterface := range secretList.Data["keys"].([]interface{}) {
		backupUID := backupUIDInterface.(string)

		secretData, err := logicalClient.Read(vaultSecretFrom + "/backup/" + backupUID)
		if err != nil {
			return errors.Wrap(err, "read secret data from vault")
		}

		_, err = logicalClient.Write(vaultSecretTo+"/backup/"+backupUID, secretData.Data)
		if err != nil {
			return errors.Wrap(err, "copy transition key")
		}
	}
	return nil
}
